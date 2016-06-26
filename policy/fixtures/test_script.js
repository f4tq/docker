
var role="control";

function validateCreate(r) {
    if (typeof facts !== 'undefined' && facts !== null) {
        console.log("Dumping facts from javascript " + JSON.stringify(facts))
    }
    console.log("validateCreate: Got it" + JSON.stringify(r));
    if (r.Config.Image == "hello-world") {
	applyProfile("coreos-defaults-json");
    }
    else {
	applyProfile("splunk");
    }

    return true
}

function facts1(r) {
    console.log("validateCreate: Got it" + facts.ansible_facts.ansible_lo);
//    console.log(getKeys(r));
    return true
}
