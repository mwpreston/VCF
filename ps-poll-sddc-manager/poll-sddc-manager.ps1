<#
.SYNOPSIS
Connects to SDDC Manager to retrieve a list of vCenters to be protected

.DESCRIPTION
This script connects to SDDC Manager, retrieving a list of vCenter Servers which have been deployed.
It then proceeds to ensure that the vCenter Servers have been added to Rubrik, and optionaly designates
top level SLA Domain protection to them.

.PARAMETER configfile
The path to a json file containing the configurations needed to execute the script

.EXAMPLE
poll-sddc-manager.ps1 -configfile c:\path\to\config
#>

#param([String]$configfile)
<#
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

#>

Import-Module c:\gitrepo\rubrik-sdk-for-powershell\Rubrik -Force
#Build Header
$Header = @{
    'Content-Type' = 'application/json'
    'Accept'       = 'application/json'
}


function Send-Request {
    param (
        [string]$Endpoint,
        [string]$Method,
        [string]$Body,
        [string]$Filter
    )

    if ($Method -eq "GET"){
        $result = Invoke-WebRequest -Uri "https://$($config.SDDCManagerConfig.sddcManagerFqdn)/$Endpoint" -Method $Method -Headers $Header
    }
    else {
        $result = Invoke-WebRequest -Uri "https://$($config.SDDCManagerConfig.sddcManagerFqdn)/$Endpoint" -Method $Method -Body $Body -Headers $Header
    }

    $result = $result | ConvertFrom-Json
    if ($Filter -and ($null -ne ($result).$Filter)) {
        $result = ($result).$Filter
    }
    return $result
}

# Load configuration file
#$config = Get-Content -Raw -Path $configfile | ConvertFrom-Json
$config = Get-Content -Raw -Path .\config.json | ConvertFrom-Json

# Load credentials
$sddcCredentials = Import-Clixml -Path $config.SDDCManagerConfig.sddcCredentials
$rubrikCredentials = Import-CliXml -Path $config.RubrikConfig.rubrikCredentials

# Connect to Rubrik Cluster
Connect-Rubrik $config.RubrikConfig.rubrikClusterFqdn -Credential $rubrikCredentials | Out-Null

# Perform initial connect to SDDC Manager and add access token to header
Write-Output "Retrieving access token from SDDC Manager"
$body = @{
    username = $sddcCredentials.username
    password = $sddcCredentials.GetNetworkCredential().password
} | ConvertTo-Json
$response = Send-Request -endpoint "v1/tokens" -method "POST" -body $body -Filter ''
$Header.Add('Authorization',"Bearer $($response.accessToken)")

# Retrieve list of SDDC Manager component credentials
Write-Output "Retrieving list of SDDC Manager component credentials"
$ComponentCredentials = Send-Request -Endpoint 'v1/credentials' -Method "GET" -Filter "elements"

# Get list of vCenters within SDDC Manager
Write-Output "Retrieving list of deployed vCenter Servers..."
$vCenterServers = Send-Request -Endpoint 'v1/vcenters' -Method "GET" -Filter 'elements'

ForEach ($vCenterServer in $vCenterServers) {
    Write-Output "Processing $($vCenterServer.fqdn)..."

    # if vCenter doesn't exist within Rubrik, add it
    if ((Get-RubrikvCenter -name $($vCenterServer.fqdn)).count -eq 0) {
        Write-Output "$($vCenterServer.fqdn) not configured in Rubrik Cluster. Proceeding to add..."
        # Get vCenter Credentials from SDDC Manager
        Write-Output "Retrieving $($vCenterServer.fqdn) credentials..."
        $vCenterInfo = $ComponentCredentials | Where {$_.credentialType -eq "SSO" -and $_.resource.resourceName -eq "$($vCenterServer.fqdn)"}
        # Convert plaintext to credential object
        $password = ConvertTo-SecureString $vCenterInfo.password -AsPlainText -Force
        $vCenterCredentialObject = New-Object System.Management.Automation.PSCredential("$($vCenterInfo.username)",$password)
        # Add vCenter to Rubrik Cluster
        Write-Output "Adding $($vCenterServer.fqdn) to Rubrik under $($vCenterInfo.username)..."
        $vCenter = New-RubrikvCenter -Hostname $($vCenterServer.fqdn) -Credential $vCenterCredentialObject
        Write-Output "$($vCenterServer.fqdn) has been added to Rubrik Cluster"
        Start-Sleep -Seconds 5
        Write-Output "Refreshing vCenter Metadata"
        $response = Get-Rubrikvcenter -Name "$($vcenterserver.fqdn)" | Update-RubrikVCenter
        Start-Sleep -SEconds 2
        $uri = $response.links.href.split("//")[8]
        DO {
            $status = (Invoke-RubrikRestCall -endpoint "vmware/vcenter/request/$uri" -Method GET).status
            Write-Output "Waiting for refresh, status is $status"
            Start-Sleep -Seconds 2
        } while ( $status -in ("RUNNING","QUEUED"))
        $status = (Invoke-RubrikRestCall -endpoint "vmware/vcenter/request/$uri" -Method GET).status
        Write-Output "Refresh complete, status is $status"
    }
    else {
        Write-Output "$($vCenterServer.fqdn) already configured in Rubrik Cluster"
    }
}




# Gather list of NSX/vCenter VMs to exclude from protection
Write-Output "Retrieving list of NSX-T VMs and vCenter Servers to exclude from protection..."
$vmsToExclude = New-Object -TypeName "System.Collections.ArrayList"

# Exclude NSX-T Managers
Write-Output "Retrieving NSX-T Manager VMs for exclusion..."
$nsxtclusters = Send-Request -Endpoint 'v1/nsxt-clusters' -Method "GET" -Filter elements
$nsxtclusters.nodes.name | ForEach { $vmsToExclude.Add($_) | Out-Null }

# Check if Edge Cluster is deployed and if so, connect to NSX-T API to retrieve VM Names
$EdgeCluster = Send-Request -Endpoint 'v1/edge-clusters' -Method "GET" -Filter elements
if ($EdgeCluster.Name -ne '') {
    Write-Output "Found $($EdgeCluster.Name) - gathering credentials"
    # Retrieve NSX-T Credentials
    $NSXInfo = $ComponentCredentials | Where {$_.credentialType -eq "API" -and $_.resource.resourceType -eq "NSXT_MANAGER"}

    # Build NSX-T Basic Auth Header
    Write-Output "Building header information to connect to $($EdgeCluster.Name) "
    $UserPassPair = "$($NSXInfo.username):$($NSXInfo.password)"
    $EncodedUserPass = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($UserPassPair))
    $BasicAuthValue = "Basic $EncodedUserPass"
    $NSXHeaders = @{
        Authorization = $BasicAuthValue
    }

    Write-Output "Retrieving list of VMs within $($EdgeCluster.Name) to exclude"
    # Match Cluster within NSX-T by displayName
    $NSXTEdgeClusterID = ((Invoke-WebRequest -Uri "https://$($NSXInfo.resource.resourceName)/api/v1/edge-clusters" -Method "GET" -Headers $NSXHeaders  | ConvertFrom-Json).results | Where-Object {$_.display_name -eq $EdgeCluster.Name}).id

    # Get Transport Nodes from NSX-T
    $NSXTEdgeClusterVMs = ((Invoke-WebRequest -Uri "https://$($NSXInfo.resource.resourceName)/api/v1/transport-nodes" -Method "GET" -Headers $NSXHeaders  | ConvertFrom-Json).results | Where-Object {$_.node_deployment_info.deployment_type -eq "VIRTUAL_MACHINE"})
    $NSXTEdgeClusterVMs | ForEach { $vmsToExclude.Add($_.display_name) | Out-Null }
}

# Add Do Not Protect SLA to Excluded VMs
Write-Output "Setting excluded VMs to DoNotProtect"
$vmstoExclude | ForEach { Get-RubrikVM $_ | Protect-RubrikVM -DoNotProtect }

# Assign SLA to vCenter
$vmSLA = Get-RubrikSLA $($config.RubrikConfig.vmSlaDomainName)
ForEach ($vCenterServer in $vCenterServers) {
    $vcenterServerId = (Get-RubrikvCenter -name $($vCenterServer.fqdn)).id

    Write-Output "Assigning $($vmSLA).name to $($vcenterServerId)"
    $body = New-Object -TypeName PSObject -Property @{'configuredSlaDomainId'="$($vmSLA.id)"}

    Invoke-RubrikRestCall -Endpoint "vmware/vcenter/$($vCenterServerId)" -Method PATCH -Body $body
}

# Add pre-backup script to SDDC Manager

# Configure pre-backup script on Rubrik

# Get NAS Info
Write-Output "Retrieving SFTP Information"

$SFTPServerFqdn = $config.ExternalSFTPConfig.SftpServerFqdn
$SFTPServerCredentials = Import-CliXml $config.ExternalSFTPConfig.SftpServerCredentials
$SFTPServerDirectory = $config.ExternalSFTPConfig.SFTPServerDirectory
$FilesetName = $config.RubrikConfig.filesetName

$SFTPSla = $config.RubrikConfig.filesetSlaDomainName

Write-Output "Checking Rubrik for existance of host ($SFTPServerFqdn) within Rubrik configuration"
$RubrikHost = Get-RubrikHost -Name "$SFTPServerFqdn"
if ($null -eq $RubrikHost) {
    Write-Output "$SFTPServerFqdn not found, proceeding to add"
    try {
        $RubrikHost = New-RubrikHost -Name "$SFTPServerFqdn"
    } catch {
        Write-Output "Please ensure that the Rubrik Backup Service is installed on $SFTPServerFqdn and try again - Exiting"
        #exit
    }
} else {
    Write-Output "$SFTPServerFqdn already exists within Rubrik"
}

# Check for fileset template existance
Write-Output "Checking Rubrik for existance of Fileset Template ($FilesetName) within Rubrik configuration"
$FilesetTemplate = Get-RubrikFilesetTemplate -Name "$FilesetName"
if ($null -eq $FilesetTemplate.Name) {
    # Create FilesetTemplate
    Write-Output "Creating fileset within Rubrik"
    $FilesetTemplate = New-RubrikFilesetTemplate -Name "$FilesetName" -Includes "$SftpServerDirectory" -OperatingSystemType "Linux"
} else {
    Write-Output "Fileset Template ($FilesetName) already exists"
}

# Create fileset from fileset template
Write-Output "Checking Rubrik for existance of Fileset ($FilesetName) assigned to Host ($SFTPServerFqdn) within Rubrik configuration"
$Fileset = Get-RubrikFileset -Name "$FilesetName"
if ($null -eq $Fileset){
    Write-Output "Creating fileset using $($FilesetTemplate.Name)"
    $Fileset = New-RubrikFileset -TemplateID "$($FilesetTemplate.id)" -HostId "$($RubrikHost.id)"
} else {
    Write-Output "Fileset ($FilesetName) already exists"
}

Write-Output "Protecting $($Fileset.Name) with $SFTPSla"
$result = Protect-RubrikFileset -id "$($Fileset.id)" -SLA $SFTPSla

# Gather file-level backup configuration
$Passphrase = $config.SDDCNSXBackupSettings.passphrase
$SFTPDirectory = $config.SDDCNSXBackupSettings.SFTPDirectory
$SFTPFingerprint = $config.SDDCNSXBackupSettings.SFTPFingerprint

#Build Backup Location
$BackupLocation = @{
    server = "$SFTPServerFqdn"
    port = "22"
    protocol = "SFTP"
    username = "$($SFTPServerCredentials.Username)"
    password = "$($SFTPServerCredentials.getNetworkCredential().password)"
    directoryPath = "$SFTPServerDirectory"
    sshFingerprint = "$SFTPFingerprint"
}
# Build Backup Schedules
if ($config.SDDCNSXBackupSettings.FrequencyToUse -eq "HOURLY") {
    $BackupSchedule = $config.SDDCNSXBackupSettings.HourlyFileLevelBackupSchedule
} else {
    $BackupSchedule = $config.SDDCNSXBackupSettings.WeeklyFileLevelBackupSchedule
}

# Configure SDDC Manager File-Level Backup
$body = @{
    encryption = @{
        passphrase = "$Passphrase"
    }
    backupLocations = @($BackupLocation)
} | ConvertTo-Json -Depth 5
Write-Host "Issuing PUT request to add backup location"
$result = Send-Request -Endpoint 'v1/system/backup-configuration' -Method "PUT" -Body $body
Start-Sleep -Seconds 30


Write-Host "Issuing PATCH to add schedule"
$body = @{
    encryption = @{
        passphrase = "$Passphrase"
    }
    backupLocations = @($BackupLocation)
    backupSchedules = @($BackupSchedule)
} | ConvertTo-Json -Depth 5

# First issue PUT and see if it works...if not, issue PATCH
$result = Send-Request -Endpoint 'v1/system/backup-configuration' -Method "PATCH" -Body $body


# Let's connect to vCenter now - first, get token with username/password
Write-Output "Configuring vCenter File Based backup to $SFTPServerFqdn"
foreach ($vcenterserver in $vCenterServers) {
    $vCenterInfo = $ComponentCredentials | Where {$_.credentialType -eq "SSO" -and $_.resource.resourceName -eq "$($vCenterServer.fqdn)"}
    # Build NSX-T Basic Auth Header
    $UserPassPair = "$($vCenterInfo.username):$($vCenterInfo.password)"
    $EncodedUserPass = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($UserPassPair))
    $BasicAuthValue = "Basic $EncodedUserPass"
    $vCenterHeaders = @{
        Authorization = $BasicAuthValue
    }
    Write-Output "Connecting to $vCenterServer and retrieving session token"
    # Establish session and rewrite headers
    $result = Invoke-WebRequest -Uri "https://$($vcenterserver.fqdn)/rest/com/vmware/cis/session" -Method Post -Headers $vCenterHeaders
    $vCenterToken = (ConvertFrom-Json $result.content).value
    Write-Output "Session token retrieved - rewriting vCenter Server headers"
    $vCenterHeaders = @{'vmware-api-session-id' = $vCenterToken}
    $vcenterheaders.add("Content-Type", "application/json")

    Write-Output "Building body for request..."
    $vCenterRecurrence = $config.vCenterFileLevelBackupSchedule.recurrence_info
    $vCenterRetention = $config.vCenterFileLevelBackupSchedule.retention_info
    $body = @{
        spec = @{
            enable = $true
            location = "sftp://$SFTPServerFqdn$SFTPDirectory"
            location_user =  "$($SFTPServerCredentials.Username)"
            location_password = "$($SFTPServerCredentials.getNetworkCredential().password)"
            parts = @("common")
            recurrence_info = $vCenterRecurrence
            retention_info = $vCenterRetention

        }
    } | convertTo-Json -Depth 5

    Write-Output "Calling API to configure vCenter backup"
    $result =    Invoke-WebRequest -Uri "https://$($vcenterserver.fqdn)/rest/appliance/recovery/backup/schedules/rubrik-scheduled" -Method Post -Body $body -Headers $vCenterHeaders
    Write-Output "All Done!"
}



