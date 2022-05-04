from datetime import datetime
import json
import threading
import requests
import os
from time import sleep

Host = "http://127.0.0.1:8090/"
repoDirectory = 'C:\\Users\\I538925\\PycharmProjects\\DAST\\Reports'
attackUrl = "http://localhost:8080/swagger/?format=openapi"
OpenApiDef = "http://localhost:8080/swagger/?format=openapi"
ReportBaseName = "ISS-V3-Burp"


def SetScope(url):
    parameters = {"url": url}

    response = requests.put(str(Host) + "/burp/target/scope",
                            params=parameters)
    print(response.status_code)


def checkAvailability():
    try:
        GetVersion()
        return True
    except:
        return False


def GetVersion():
    parameters = {}

    response = requests.get(str(Host) + "/burp/versions",
                            params=parameters)

    if response.status_code == 200:
        jsonresponse = response.json()
        answer = jsonresponse["burpVersion"]
        print(str(answer))


def IsInScope(url):
    parameters = {"url": url}

    response = requests.get(str(Host) + "/burp/target/scope",
                            params=parameters)
    if response.status_code == 200:
        jsonresponse = response.json()
        answer = jsonresponse["inScope"]
        print(answer)


def GetSpiderStatus():
    parameters = {}

    response = requests.get(str(Host) + "/burp/spider/status",
                            params=parameters)
    if response.status_code == 200:
        jsonresponse = response.json()
        answer = jsonresponse["spiderPercentage"]
        print("Spider status: " + str(answer) + "%")
        return answer


def GetScannerStatus():
    parameters = {}

    response = requests.get(str(Host) + "/burp/scanner/status",
                            params=parameters)
    if response.status_code == 200:
        jsonresponse = response.json()
        answer = jsonresponse["scanPercentage"]
        print("Scanner Status: " + str(answer) + "%")
        return answer
    print("scanner error")
    return 100


def StartSpider(url):
    parameters = {"baseUrl": url}

    response = requests.post(str(Host) + "/burp/spider",
                             params=parameters)
    print(response.status_code)


def StartPassiveScan(url):
    parameters = {"baseUrl": url}

    response = requests.post(str(Host) + "/burp/scanner/scans/passive",
                             params=parameters)
    print(response.status_code)


def StartActiveScan(url):
    parameters = {"baseUrl": url}

    response = requests.post(str(Host) + "/burp/scanner/scans/active",
                             params=parameters)
    print(response.status_code)


def CreateHTMLReport(url, reportName):
    parameters = {"urlPrefix": url, "reortType": "HTML"}

    response = requests.get(str(Host) + "/burp/report",
                            params=parameters)
    if response.status_code == 200:
        fileHandlerReport = open(str(repoDirectory) + "\\" + str(reportName) + ".html", "a")
        fileHandlerReport.write(response.content.decode('utf-8'))
        fileHandlerReport.close()
        print("Report generated Successfully")
    else:
        print("error while saving report")


# closes Burp API
def Close():
    parameters = {}

    response = requests.get(str(Host) + "/burp/stop",
                            params=parameters)
    print("Closed: " + str(response.status_code))


def WaitForAvaiability():
    while not checkAvailability():
        print("not available")
        sleep(10)
    print("available")


def startBurp():
    os.system(
        'cmd /c "cd C:\\Users\\I538925\\AppData\\Local\\Programs\\BurpSuitePro & burp-rest-api.bat --headless.mode=false"')


def runSpider(entry):
    StartSpider(entry)
    while GetSpiderStatus() != 100:
        sleep(10)


def runScanner(entry):
    StartPassiveScan(entry)
    while GetScannerStatus() != 100:
        sleep(10)
    StartActiveScan(entry)
    while GetScannerStatus() != 100:
        sleep(10)


def runDAST():
    WaitForAvaiability()
    SetScope(attackUrl)
    runSpider(OpenApiDef)
    runScanner(attackUrl)
    CreateHTMLReport(attackUrl, ReportBaseName + str(datetime.now()))
    Close()


def FullScan():
    trd1 = threading.Thread(target=startBurp)
    trd2 = threading.Thread(target=runDAST)
    trd1.start()
    trd2.start()


startBurp()
