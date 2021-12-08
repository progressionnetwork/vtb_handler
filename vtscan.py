#!/usr/bin/python
# Virus Total API Integration Script
# Built on VT Test Script from: Adam Meyers ~ CrowdStrike
# Rewirtten / Modified / Personalized: Chris Clark ~ GD Fidelis CyberSecurity
# If things are broken let me know chris@xenosec.org
# No Licence or warranty expressed or implied, use however you wish! 

import json, urllib, hashlib, re, sys
from pprint import pprint
from urllib.request import urlopen


class vtAPI():
    def __init__(self):
        self.api = 'e0b774e1eaf162e8ba17eb572ad9834cffb6b08e5b96030023b2be79031f7cea'
        self.base = 'https://www.virustotal.com/vtapi/v2/'

    def getReport(self, md5):
        param = {'resource': md5, 'apikey': self.api}
        url = self.base + "file/report"
        data = urllib.parse.urlencode(param)
        data = data.encode('utf-8')
        result = urlopen(url, data)
        jdata = json.loads(result.read())
        return jdata

    def rescan(self, md5):
        param = {'resource': md5, 'apikey': self.api}
        url = self.base + "file/rescan"
        data = urllib.parse.urlencode(param)
        data = data.encode('utf-8')
        result = urlopen(url, data)
        print("\n\tVirus Total Rescan Initiated for -- " + md5 + " (Requery in 10 Mins)")


# Md5 Function

def checkMD5(checkval):
    if re.match(r"([a-fA-F\d]{32})", checkval) == None:
        md5 = md5sum(checkval)
        return md5.upper()
    else:
        return checkval.upper()


def md5sum(filename):
    fh = open(filename, 'rb')
    m = hashlib.md5()
    while True:
        data = fh.read(8192)
        if not data:
            break
        m.update(data)
    return m.hexdigest()


def parse(it, md5, verbose):
    ret = False

    if it['response_code'] == 0:
        print(md5 + " -- Not Found in VT")
        return ret

    print("\n\tResults for MD5: ", it['md5'], "\n\n\tDetected by: ", it['positives'], '/', it['total'], '\n')
    if 'Sophos' in it['scans']:
        print('\tSophos Detection:', it['scans']['Sophos']['result'], '\n')
        ret = True
    if 'Kaspersky' in it['scans']:
        print('\tKaspersky Detection:', it['scans']['Kaspersky']['result'], '\n')
        ret = True
    if 'ESET-NOD32' in it['scans']:
        print('\tESET Detection:', it['scans']['ESET-NOD32']['result'], '\n')
        ret = True
    if 'Avira' in it['scans']:
        print('\tESET Detection:', it['scans']['Avira']['result'], '\n')
        ret = True

    print('\tScanned on:', it['scan_date'])

    if verbose == True:
        print('\n\tVerbose VirusTotal Information Output:\n')
        for x in it['scans']:
            print('\t', x, '\t' if len(x) < 7 else '', '\t' if len(x) < 14 else '', '\t', it['scans'][x]['detected'],
                  '\t', \
                  it['scans'][x]['result'])

    return ret