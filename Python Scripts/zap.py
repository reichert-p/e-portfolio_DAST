from time import sleep
import time
import requests

apikey = '' # copy your Api Key here
port = '8082'
host = 'http://localhost:' + port
reportLocation = 'C:\\Users...' # maintain location where reports should get stored
openAPI_location = 'http://localhost:8080/api/schema/'
attackScope = 'http://localhost:8080.*'  # Attention: this is a regex of all URLs that will be attacked.
# Never make this to general to stay in a legal environment
testname = 'Beispielbericht'  # name for the report
# [scriptName,scriptType,scriptEngine,fileName(aka path),scriptDescription]
scripts = [
    ['reflected XSS.js', 'active', 'ECMAScript : Graal.js', 'C:\\Users...', 'custom fuzzing for reflected XSS'],
    ['stored XSS eas.js', 'active', 'ECMAScript : Graal.js', 'C:\\Users...', 'custom fuzzing for stored XSS in Ethicsassessmentsoftware'],
]

# in case you want to start your scan with an existing Session, simply pass the name of that session
def loadSession(sessionName):
    parameters = {'apikey': apikey, 'name': sessionName}
    response = requests.get(str(host) + "/JSON/core/action/loadSession/",
                            params=parameters)
    if (response.status_code == 200):
        jsonResponse = response.json()
        state = str(jsonResponse["Result"])
        if (state == "OK"):
            return True
        else:
            print(state)
    else:
        print("API error while loading Session")
    return False

# deletes previous vulnerabilities and creates a new Session to start a new scan
def newSession():
    deleteExistingVulnerabilities()
    parameters = {"apikey": apikey}
    response = requests.get(str(host) + "/JSON/core/action/newSession/",
                            params=parameters)
    if (response.status_code == 200):
        jsonResponse = response.json()
        state = str(jsonResponse["Result"])
        if (state == "OK"):
            return True
    else:
        print(response.status_code)
    return False

# deletes existing vulnerabilities
def deleteExistingVulnerabilities():
    parameters = {"apikey": apikey}
    response = requests.get(str(host) + "/JSON/alert/action/deleteAllAlerts/",
                            params=parameters)
    if (response.status_code == 200):
        jsonResponse = response.json()
        state = str(jsonResponse["Result"])
        if (state == "OK"):
            return True
    else:
        print("couldn't delete existing vulnerabilities")
        return False

# loads an OpenAPI specification from an online location where the host equals the location
# for offline specifications or manually spcified host change endpoint/add parameter
def loadOpenAPI(url):
    parameters = {"apikey": apikey, "url": url}
    response = requests.get(str(host) + "/JSON/openapi/action/importUrl/",
                            params=parameters)
    if response.status_code == 200:
        print("OpenAPI specification loaded successfully")
        return True
    else:
        print("An Error while parsing the OpenAPI specification occurred")
        return False


# generates a report of all Alerts in HTML format with var reportName and a timestamp as name in
# var reportLocation specified location. For more report options, check /reports/action/generate/ endpoint
def generateHTMLReport(reportName):
    parameters = {"apikey": apikey}
    response = requests.get(str(host) + "/OTHER/core/other/htmlreport/",
                            params=parameters)
    if (response.status_code == 200):
        current_time = time.localtime()
        fileHandlerReport = open(
            # timestamp in report name to prevent losing reports due to duplicated names
            str(reportLocation) + "\\" + str(reportName) + time.strftime('%d%b%Y%H%M%S',
                                                                        current_time) + ".html", "a")
        fileHandlerReport.write(response.content.decode('utf-8'))
        fileHandlerReport.close()
        return True
    else:
        print("Error occured while trying to generate HTML report")
        return False

# monitors the progress of the scan with the given ID in percent to the console
def activeScanProgress(scanID):
    parameters = {"apikey": apikey, "scanID": scanID}
    response = requests.get(str(host) + "/JSON/ascan/view/status/",
                            params=parameters)
    if (response.status_code == 200):
        jsonresponse = response.json()
        print('Scanfortschritt: ' + str(jsonresponse['status'] + "%"))
        return str(jsonresponse['status'])
    return "False"

# starts an active scan of the default context with the passed scan policy
# returns the scan ID of the started Scan
def startActiveScan(scanPolicyName):
    contextID = 1  # default context
    parameters = {"apikey": apikey, "contextId": contextID, "scanPolicyName": scanPolicyName}
    response = requests.get(str(host) + "/JSON/ascan/action/scan/",
                            params=parameters)
    if (response.status_code == 200):
        jsonresponse = response.json()
        return str(jsonresponse["scan"])
    else:
        print('failed to start active scan')
        return 'ERROR'

# runs full active scan and regularily updates progress to terminal
def runActiveScan(scanPolicyName):
    scanID = startActiveScan(scanPolicyName)
    if scanID != 'ERROR':
        progress = activeScanProgress(scanID)
        while progress != str(100) and progress != 'ERROR' :
            sleep(10)
            progress = activeScanProgress(scanID)
    else:
        print(scanID)

# includes and enables all scripts specified in var scripts line 13
def setScripts():
    for script in scripts:
        parameters = {"apikey": apikey, "scriptName": script[0], "scriptType": script[1], "scriptEngine": script[2],
                                        "fileName": script[3], "scriptDescription": script[4]}
        response = requests.get(str(host) + "/JSON/script/action/load/",
                                params=parameters)
        if response.status_code == 200:
            response = requests.get(str(host) + "/JSON/script/action/enable/",
                                    params=parameters)
        else:
            print("error while including script: " + script[0])



# includes regex from line 10 in default context, which allows it to get scanned and is standard scope for ascan
def includeInContext(url):
    parameters = {"apikey": apikey, "contextName": "Default Context", "regex": url}
    response = requests.get(str(host) + "/JSON/context/action/includeInContext/",
                            params=parameters)
    if response.status_code == 200:
        return True
    else:
        print("An Error while changing the context occurred")
        return False

# puts together all other for complete DAST
def runFullScan():
    if newSession():
        if loadOpenAPI(openAPI_location):
            includeInContext(attackScope)
            setScripts()
            runActiveScan("Default Policy")
            runActiveScan("scripts only")
            generateHTMLReport(testname)
    else:
        print("ERROR-Possibly an API Error")

# for time measuring purposes
def func():
    start = time.perf_counter()
    runFullScan()
    print("Scan Completed Execution in" + str({time.perf_counter() - start}) + "seconds")

func()
