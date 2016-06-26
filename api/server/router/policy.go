package router

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"github.com/Sirupsen/logrus"
	//containertypes "github.com/docker/engine-api/types/container"
	"github.com/docker/engine-api/types"
	"github.com/robertkrimen/otto"
	"os"
	"time"
	"errors"
	"fmt"
	"strings"
	"path/filepath"

)

/*
From docker/docker:

dockerd  -D --client-policy-config-file policy/policy.json



Imports and compiles javascript files

Generate facts with a tool like ansible

$ ansible --tree /tmp/foo localhost -m setup

which produces a file of facts about localhost in /tmp/foo/localhost

*/
type Policy interface {
	ValidateCreate(params *types.ContainerCreateConfig) error;
}
type LoggingDriver interface {
     Driver() string
}

type PolicyConfig struct {
        Logging LoggingOptions
        LoggingProfiles map[string]LoggingDriver
        Validator ValidatorT
}
// facts are injected into javascript context
type Facts interface{}

// The main runtime policy held by containerRouter
type PolicyT struct{
        Config *PolicyConfig `json:"PolicyConfig"`
        script *otto.Script
        libs []*otto.Script
        facts Facts
}
// ValidatorT holds javascript information
type ValidatorT struct {
            Timeout int `json:"func_timeout,omitempty"`
            CreateFunc string `json:"createfunc,omitempty"`
            JSMain string `json:"jsmain"`
	    JSLibdir string `json:"jslibdir"`
            JSPreloads []string `json:"jspreload,omitempty"`
            FactFile string `json:"facts,omitempty"`
}

// concrete types used for json marshalling only
type JsonT struct {
        Maxfiles string  `json:"max-file,omitempty"`
        Maxsize  string `json:"max-size,omitempty"`
}
type SyslogT struct {
        Syslogtag string `json:"syslog-tag,omitempty"`
        SyslogAddress string `json:"syslog-address,omitempty"`
        SyslogFacility string `json:"syslog-facility,omitempty"`
        SyslogFormat   string `json:"syslog-format,omitempty"`
}
type SplunkT struct {
        URLKey string `json:"splunk-url,omitempty"`
        TokenKey string `json:"splunk-token,omitempty"`
        SourceKey string `json:"splunk-source,omitempty"`
        SourceTypeKey string `json:"splunk-sourcetype,omitempty"`
        IndexKey string `json:"splunk-index,omitempty"`
        CAPathKey string `json:"splunk-capath,omitempty"`
        CANameKey string `json:"splunk-caname,omitempty"`
        InsecureSkipVerifyKey string `json:"splunk-insecureskipverify,omitempty"`
        EnvKey string `json:"env,omitempty"`
        LabelsKey string  `json:"labels,omitempty"`
        TagKey string `json:"tag,omitempty"`
}

type FluentT struct{
        AddressKey string `json:"fluentd-address,omitempty"`
        BufferLimitKey string `json:"fluentd-buffer-limit,omitempty"`
        RetryWaitKey string `json:"fluentd-retry-wait,omitempty"`
        MaxRetriesKey string `json:"fluentd-max-retries,omitempty"`
        AsyncConnectKey string  `json:"fluentd-async-connect,omitempty"`
}
type AwslogsT struct{
	RegionKey         string `json:"awslogs-region,omitempty"`
	RegionEnvKey      string    `json:"AWS_REGION,omitempty"`
	LogGroupKey       string    `json:"awslogs-group,omitempty"`
	LogStreamKey      string    `json:"awslogs-stream,omitempty"`
}

type LoggingOptions struct {
        Enforce        bool   `json:"enforce"`
        Default_logger string `json:"default"`
}
// Pseudo PolicyConfig used to read hash of named logging profiles
type JSONPolicyConfig struct {
        Logging LoggingOptions `json:"Logging"`
        RawProfiles map[string]json.RawMessage  `json:"LoggingProfiles"`
        Validator ValidatorT `json:"Validator"`
}

// halt is channel message used to stop javascript execution if
// Timeout is exceeded

var halt = errors.New("timeout")
// deniedByPolicy is sent back to router
var deniedByPolicy = errors.New("Denied by policy")

func NewPolicy(cfg *PolicyConfig) (*PolicyT,error){
        logrus.Debugf("JSPreloads: %+v\n",cfg)
        p := &PolicyT{
                Config: cfg,
                libs: make([]*otto.Script,len(cfg.Validator.JSPreloads),len(cfg.Validator.JSPreloads)),
        }
	var jsdirs []string
	curdir,_ := os.Getwd()
	// Canonicalize the js directories.  Only add them to the list if they are in fact directories
	if cfg.Validator.JSLibdir != "" {
		for _,path := range strings.Split(cfg.Validator.JSLibdir,":") {
			if !strings.HasSuffix(path,"/") {
				path += "/"
			}
			dir,err := filepath.Abs(filepath.Dir(path))
			if err != nil {
				logrus.Errorf("Path '%s' does not resolve - %v\n", path,err)
				return nil,err
			} else {
				info, err := os.Stat(dir)

				if err != nil || !info.IsDir() {
					logrus.Errorf("js path is not directory %s - %v\n", dir, err)
					return nil, err
				}
				logrus.Debugf("Canonical js dir %s is valid\n",dir)
				jsdirs = append(jsdirs, dir)
			}

		}

	} else {
		jsdirs=append(jsdirs,curdir)
	}
	var jsfiles []string
	var compiled_scripts []*otto.Script
	if cfg.Validator.JSPreloads != nil{
		jsfiles = cfg.Validator.JSPreloads
	}
	// main is last
	jsfiles = append(jsfiles,cfg.Validator.JSMain )
	// resolve & canonicalize js files.
        for _,ff :=range jsfiles {
		var fp string
		for _,jsd := range jsdirs {
			targ := filepath.Join(jsd, ff)
			if finfo, err := os.Stat(targ); err != nil || finfo.IsDir() {
				logrus.Debugf("js '%s' - not found, ignoring  err: %v to continue looking\n", targ,err)
				continue
			} else {
				fp = targ
			}
		}
		if fp == "" {
			msg := fmt.Sprintf("Missing javascript file '%s' couldn't be resolved in dirs: %v\n",jsdirs)
			return nil,errors.New(msg)
		}
		// compile javascript file
		script,err := loadPluginRuntime(fp)

		if err != nil {
			return nil,errors.New(fmt.Sprintf("Unknown js error in file '%s' -  %v\n",ff,err))
                } else {
			compiled_scripts = append(compiled_scripts,script)
                }
        }
	p.script,p.libs=compiled_scripts[len(compiled_scripts)-1],compiled_scripts[0:len(compiled_scripts)-1]


        if cfg.Validator.FactFile != "" {
		// facts are read from the file system.
		// They are injected into the validator javascript context to aid decision making
		// ansible --tree /tmp/foo localhost -m setup will generate host facts in format
		// At the moment, these are read on daemon startup but could be made to detect changes
		// if read on a per javascript runtime basis
                if facts, err := readFacts(cfg.Validator.FactFile); err != nil {
                        return nil, errors.New(fmt.Sprintf("Factfile problem: %v",err))
                } else{
                        p.facts = Facts(facts)
                }
        }

   return p,nil
}
/*
Read facts from a file that are in json form.
 */
func readFacts(configFile string)(*map[string]interface{}, error) {
        b, err := ioutil.ReadFile(configFile)
        if err != nil {
                logrus.Fatalf("Error reading file: %s - %v", configFile, err)
                return nil, err
        }
        jsonConfig := make(map[string]interface{});
        var reader io.Reader = bytes.NewReader(b)
        if err := json.NewDecoder(reader).Decode(&jsonConfig); err != nil {
                logrus.Fatalf("JSON Error reading file: %s - %v\n", configFile, err)
                return nil, err
        }
        logrus.Debugf("readFacts from '%s':\n\t %T %v\n", configFile, jsonConfig, jsonConfig)

        return &jsonConfig, err

}
/*
Reads a Policy file from 'configFile' returning a pointer to Policy
 */
func GetPolicyConfiguration(configFile string)(*PolicyConfig, error) {
        b, err := ioutil.ReadFile(configFile)
        if err != nil {
                logrus.Fatalf("Error reading file: %s - %v", configFile,err)
                return nil, err
        }
        var jsonConfig PolicyConfig;
        var reader io.Reader = bytes.NewReader(b)
        if err := json.NewDecoder(reader).Decode(&jsonConfig); err != nil {
                logrus.Fatalf("JSON Error reading file: %s - %v\n", configFile,err)
                return nil, err
        }
        logrus.Debugf("GetPolicyConfiguration from '%s'\n\t%v\n", configFile,jsonConfig)

        return &jsonConfig,err

}
/*
Reads & compiles the passed name as ECMAScript.
 Returns: *otto.Script
 */
func loadPluginRuntime(name string) (*otto.Script,error) {
     f, err := os.Open(name)
     if err != nil {
        if os.IsNotExist(err) {
           logrus.Errorf("Policy Error: script: %s %v", name,err)
           return nil,err
        }
        logrus.Errorf("Policy Error: script: %s %v", name,err)
    }
    defer f.Close()
    buff := bytes.NewBuffer(nil)

    if _, err := buff.ReadFrom(f); err != nil {
        logrus.Errorf("Policy Error: script: %s %v", name,err)
            return nil,err
    }

    logrus.Debugf("Compiling JS: %s\n",name)
    vm:= otto.New()
    script, err := vm.Compile(name,buff)
    if err != nil {
       logrus.Errorf("Problem compiling %s  err: %v", name,err)
          return nil, err
    }
    return script, nil
}
/*
Policy interface implemetation.  Called from container_routes
 */
func (pol *PolicyT) ValidateCreate(params *types.ContainerCreateConfig) error {
	val := pol.jsInvoke("validateCreate",params)
        if !val {
                return deniedByPolicy
        }
        return nil
}
/*
Main ecmascript invoker.
Given an operation and arguments:
- It constructs a new javascript runtime injecting into it:
  - all pre-compiled javascript scripts PolicyT.libs
  - the main pre-compiled javascript main function
  - the facts if present - PolicyT.facts into the global facts variable.
- It passes a JSON marshaled/unmarshalled rep of the args (for safety and js <->golang mapping
- Only thing mutable from javascript is via explicitely provided  golang functions injected into the javascript namespace.
  These are:
     - applyProfile:
        - Implement function 'applyProfile(profile_name)' which resolves against PolicyConfig.LoggingProfiles map

- It also guards against any javascript call/operation from taking more than Timeout seconds default: 2.0

 */
func (pol *PolicyT) jsInvoke(operation string, args ...interface{} ) (bool) {

        runtime := otto.New()
	// setup and handle timeouts
        runtime.Interrupt = make(chan func(), 1)
        start := time.Now()
        defer func() {
                duration := time.Since(start)
                if caught := recover(); caught != nil {
                        if caught == halt {
                                logrus.Errorf("Timeout: - Policy took too long. Stopping after: %v\n", duration)
                                return
                        }
                        logrus.Errorf("Trouble within js: %v", caught)
                        return
                }
                logrus.Debugf( "Ran code successfully: %v\n", duration)
        }()

        go func() {
                time.Sleep(time.Duration(pol.Config.Validator.Timeout) * time.Second) // Stop after two seconds
                runtime.Interrupt <- func() {
                        panic(halt)
                }
        }()
        // setup library files
        for index,lib := range pol.libs {
                if _,err := runtime.Run(lib) ; err != nil {
                        logrus.Errorf("Error injecting %v into runtime: %v\n", pol.Config.Validator.JSPreloads[index],err)
                        return false
                }
        }
	// clean up values for the 4 javascript types and to effectively make the
	// types immutable
	logrus.Debugf("raw args: %+v",args)
	clean,err := json.Marshal(args[0])
	if err != nil {
		logrus.Errorf("Error marshalling context to javascript %v\n",err)
		return false
	}
	var honey map[string]interface{}
	err = json.Unmarshal(clean,&honey)
	if err != nil {
		logrus.Errorf("Error unmarshalling context to javascript %v\n",err)
		return false
	}
        logrus.Debugf("%s argument %+v\n", operation,honey)

        if pol.facts != nil {
                // set the user provided facts into the javascript context
		mp := pol.facts.(*map[string]interface{})
                if err := runtime.Set("facts", *mp) ; err != nil {
                        logrus.Errorf("Error setting facts into policy runtime %v\n",err)
                        return false
                }
        }
        // put the script is a fresh runtime
        if _, err :=runtime.Run(pol.script); err != nil {
                logrus.Error(err)
                return false
        }
	runtime.Set("applyProfile", func(call otto.FunctionCall) otto.Value {
		if operation == "validateCreate" {
			logrus.Debugf("applyProfile: '%s'\n", call.Argument(0).String())
			createOptions := args[0].(*types.ContainerCreateConfig)
			logrus.Debugf("applyProfile: createOptions %T\n",createOptions)

			cfg := createOptions.HostConfig.LogConfig
			// clear the map in case something was set
			for k := range cfg.Config {
				delete(cfg.Config, k)
			}
			logrus.Debugf("applyProfile: logConfig %T %v\n",cfg,cfg)
			profile := pol.Config.LoggingProfiles[call.Argument(0).String()]
			logrus.Debugf("pol.Config.LoggingProfiles: %+v\n",pol.Config.LoggingProfiles)
			logrus.Debugf("applyProfile: profile %T\n",profile)
			profile_bytes,err := json.Marshal(profile)
			logrus.Debugf("applyProfile: profile_bytes %+v err: %v\n",profile,err)
			if err != nil {
				panic(err)
			}
			err = json.Unmarshal(profile_bytes,&cfg.Config)
			logrus.Debugf("applyProfile: after marshal logConfig %T %v\n",cfg,cfg)
			if err != nil {
				panic(err)
			}
			cfg.Type = profile.Driver()
		}
		return otto.Value{}
	})

        // call an explicit function which must return a bool or it fail

        if result,err := runtime.Call(operation,nil,honey); err != nil {
                logrus.Errorf("You must define 'function %s(r)' %+v\n",operation,err)
                return false
        }  else {
                logrus.Debugf("Results: %+v \n",result)
                return true
        }

}
/// Marshalling functions
func (f *FluentT) Driver() string {
    return "fluent"
}
func (p *FluentT) unmarshal(raw json.RawMessage) bool {
     if err := json.Unmarshal(raw, p); err != nil {
        return false
        }
     return p.AddressKey != "" || p.BufferLimitKey != "" || p.RetryWaitKey != "" || p.MaxRetriesKey != "" || p.AsyncConnectKey != ""
}
func (f *JsonT) Driver() string {
    return "json-file"
}
func (p *JsonT) unmarshal(raw json.RawMessage) bool {
     if err := json.Unmarshal(raw, p); err != nil {
        return false
     }
     return p.Maxfiles != "" || p.Maxsize != ""
}

func (f *SyslogT) Driver() string {
    return "syslog"
}
func (p *SyslogT) unmarshal(raw json.RawMessage) bool {
     if err := json.Unmarshal(raw, p); err != nil {
        return false
     }
     return p.Syslogtag != "" || p.SyslogAddress != "" || p.SyslogFacility != "" || p.SyslogFormat != ""
}

func (f *SplunkT) Driver() string {
    return "splunk"
}
func (p *SplunkT) unmarshal(raw json.RawMessage) bool {
     if err := json.Unmarshal(raw, p); err != nil {
        return false
     }
     return p.URLKey != "" && p.TokenKey != ""
}

func (f *AwslogsT) Driver() string {
    return "awslogs"
}
func (p *AwslogsT) unmarshal(raw json.RawMessage) bool {
     if err := json.Unmarshal(raw, p); err != nil {
        return false
     }
     return p.RegionEnvKey != "" || p.LogGroupKey != "" || p.LogStreamKey != "" || p.RegionKey != ""
}

func (self *PolicyConfig) UnmarshalJSON(raw []byte ) error {
	var jsonConfig JSONPolicyConfig

	if err := json.Unmarshal(raw, &jsonConfig); err != nil {
		return err
	}
	if jsonConfig.Validator.Timeout == 0 {
		jsonConfig.Validator.Timeout = 2
	}

	self.LoggingProfiles = make(map[string]LoggingDriver)
	self.Logging = jsonConfig.Logging
	self.Validator = jsonConfig.Validator

        for k,v := range jsonConfig.RawProfiles {
             fluent_driver := new (FluentT)
             if fluent_driver.unmarshal(v) {
                  self.LoggingProfiles[k] = fluent_driver
                  continue
             }
             json_driver := new(JsonT)
             if json_driver.unmarshal(v) {
                  self.LoggingProfiles[k] = json_driver
                  continue
             }
             splunk_driver := new(SplunkT)
             if splunk_driver.unmarshal(v) {
                  self.LoggingProfiles[k] = splunk_driver
                  continue
             }
             syslog_driver := new(SyslogT)
             if syslog_driver.unmarshal(v) {
                  self.LoggingProfiles[k] = syslog_driver
                  continue
             }
             aws_driver := new(AwslogsT)
             if aws_driver.unmarshal(v) {
                  self.LoggingProfiles[k] = aws_driver
                  continue
             }

             logrus.Errorf("Unknown driver %s\n", k)

        }
        logrus.Debugf("PolicyConfig::unmarshal - %T\n%+v\n\n",self,self)
        return nil
}



//// javascript functions

