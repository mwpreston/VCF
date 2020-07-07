#!/bin/bash

targetfolder="/nfs/vmware/vcf/nfs-mount/backup/inventory"
endpoints=( clusters domains esxis hosts nsxmanagers pscs sddcmanagercontrollers vcenters vcfservices vds vras vrlis vrops vrslcms )

for endpoint in "${endpoints[@]}"
do
  curl -H 'Application: accept/json' http://localhost/inventory/$endpoint | python -m json.tool > $targetfolder/$endpoint.json
done


curl -H 'Application: accept/json' http://localhost/licensing/licensekeys | python -m json.tool > $targetfolder/licensekeys.json
curl -H 'Application: accept/json' http://localhost:7100/networkpools | python -m json.tool > $targetfolder/networkpools.json
curl -H 'Application: accept/json' http://localhost/security/password/vault | python -m json.tool > $targetfolder/passwords.json

# Get NSX username and password
NSXUSER=$(cat $targetfolder/passwords.json | python -c "exec(\"import sys, json;\njsonarray = json.load(sys.stdin);\nfor dict in jsonarray:\n if dict['entityType'] == 'NSX_MANAGER' and dict['credentialType'] == 'API':\n  print dict['username']\")")
NSXPASS=$(cat $targetfolder/passwords.json | python -c "exec(\"import sys, json;\njsonarray = json.load(sys.stdin);\nfor dict in jsonarray:\n if dict['entityType'] == 'NSX_MANAGER' and dict['credentialType'] == 'API':\n  print dict['password']\")")
NSXIP=$(cat $targetfolder/passwords.json | python -c "exec(\"import sys, json;\njsonarray = json.load(sys.stdin);\nfor dict in jsonarray:\n if dict['entityType'] == 'NSX_MANAGER' and dict['credentialType'] == 'API':\n  print dict['entityIpAddress']\")")

#DUMP NSX Backup settings
curl --user $NSXUSER:$NSXPASS -H 'Application: accept/json' -k https://$NSXIP/api/1.0/appliance-management/backuprestore/backupsettings | xmllint --format - > $targetfolder/nsxbackupsettings.xml

#Domain specific settings
cat $targetfolder/domains.json | python -c "exec(\"import sys, json, urllib2;\njsonarray = json.load(sys.stdin);\nfor dict in jsonarray:\n url='http://localhost/inventory/domains/' + dict['id'] + '/inventory';\n req = urllib2.Request(url);\n f = urllib2.urlopen(req);\n for x in f:\n  print(x);\nf.close();\")" | python -m json.tool > $targetfolder/domainspecific.json 

#Network Pool specific inventory
cat $targetfolder/networkpools.json | python -c "exec(\"import sys, json, urllib2;\njsonarray = json.load(sys.stdin);\nfor dict in jsonarray:\n url='http://localhost:7100/networkpools/' + dict['id'] + '/networks';\n req = urllib2.Request(url);\n f = urllib2.urlopen(req);\n for x in f:\n  print(x);\nf.close();\")" | python -m json.tool > $targetfolder/networkpoolspecific.json
