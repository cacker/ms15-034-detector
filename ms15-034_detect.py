"""
    MS15-034 detection script
    Checks HTTP or HTTPS servers for vulnerability to MS15-034 (CVE-2015-1635)
"""
import requests
import sys

if len(sys.argv) < 2:
    print "Usage: {0} <target_address>".format(sys.argv[0])
    sys.exit(1)

target = sys.argv[1]
if target.find('http') < 0:
    target = 'http://' + target

detect_headers = {'Range': 'bytes=0-18446744073709551615'}
reply = requests.get(target, headers = detect_headers)

if reply.status_code == 416:
    print "Server looks vulnerable"
elif reply.status_code == 400:
    print "Server looks patched"
elif reply.status_code == 401 or reply.status_code == 403:
    print "Server requires auth - can't check status"
else:
    print "Can't determine server status (unknown response)"
    print reply.status_code, "/", reply.text
