# VCF
Collection of Scripts/Things dealing with VCF

## bash-document-sddc-inventory
This bash file can be placed on the SDDC Manager and is meant to be executed before each backup takes place. The script in turn will document a variety of information about workload domains, esxi versions, etc.

## ps-poll-sddc-manager
This is a PowerShell script which is meant to be scheduled. It will check SDDC Manager for any newly deployed workload domains and vCenters and add them to Rubrik. Also, file-based backups are configured to an inputted share and the share protected by Rubrik.

