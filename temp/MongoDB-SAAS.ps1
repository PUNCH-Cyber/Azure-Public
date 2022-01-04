<#
    TITLE:          MongoDB Atlas Data Connector for Microsoft Sentinel
    VERSION:        1.2
    LAST MODIFIED:  12/29/2021
    AUTHOR:         @punchcyber.com
    
    DESCRIPTION:
    The following data connector retreives the following log types:
        * Org Events
        * Project Events 
        * Audit Logs 
        * Cluster Access Logs

    ENVIRONMENT VARIABLES:
        * debug - (true/false) verbose logging toggle
        * publicKey - MongoDB API username/public key
        * priaveKey - MongoDB API password/private key
        * timeInterval - initial log event lookback timeframe
        * workspaceId - Log Analytics workspace Id
        * workspaceKey - Log Analytics workspace key
    
    MONGODB API LIMITATIONS:
        * 100 API requests per minute, per Project
        * Maximum records per API response is 500
        * Cluster Access Logs: a) maximum record is set to 2000, no header info is returned in the API response, this information would provide any pagningation information, any records past 2000 events will be lost.

    REFERENCES:
        * https://subscription.packtpub.com/book/data/9781839210648/1/ch01lvl1sec09/mongodb-atlas-organizations-projects-users-and-clusters
    
#>
# Input bindings are passed in via param block.
param($Timer)

# Get the current universal time in the default string format.
$currentUTCtime = (Get-Date).ToUniversalTime()

# The 'IsPastDue' property is 'true' when the current function invocation is later than scheduled.
if ($Timer.IsPastDue) {
    Write-Host "PowerShell timer is running late!"
}

#===================================== VARIABLES ==========================================================#

# DEBUG - Verbose logging toggle
if($env:debug -eq $true){
    $DebugPreference = "Continue" # Enabled Debugging
} else {
    $DebugPreference = "SilentlyContinue" # Disable Debugging
}

# MangoDB Atlas API
$publicKey = $env:publicKey
$privateKey = $env:privateKey
$global:baseUrl = "https://cloud.mongodb.com/api/atlas/v1.0"
$global:timeInterval = $env:timeInterval  # the last 'x' minutes (e.g. 5 = the last 5 mins)
$endTime = $currentUTCtime
# Define the number of events per API response, limits: up to 500. Lower the record limit risks API request limitations.
$global:responseRecordLimit = 500
$global:apiRequestCounter = @()

# Compile Credentials
[SecureString]$secStringPassword = ConvertTo-SecureString $PrivateKey -AsPlainText -Force
[PSCredential]$global:credentials = New-Object System.Management.Automation.PSCredential ($PublicKey, $secStringPassword)

# Log Analytics 
$global:workspaceId = $env:workspaceId
$global:workspaceKey = $env:workspaceKey
$global:tableName = "MongoDB"
$TimeStampField = "DateValue"

# General
$cwd = (Get-Location).Drive.Root
$global:checkPointFile = "$($cwd)home\LogFiles\AtlasAPICheckpoints.csv"
$global:auditLogDir = "$($cwd)home\LogFiles\"
#================================== GENERAL FUNCTIONS =====================================================#

# Function to retrieve the checkpoint start time of the last successful API call for a given logtype. Checkpoint file will be created if none exists.
function GetStartTime ($LogType, $EndTime, $OrgID = "", $GroupID = "", $ClusterName = "", $Hostname = "", $Filename = "") {

    $firstStartTimeRecord = $EndTime.AddMinutes(-$timeInterval)

    if ([System.IO.File]::Exists($checkpointFile) -eq $false) {
        $firstCheckpointEntry = [PSCustomObject]@{
            OrgId = $OrgID
            GroupId = $GroupID
            ClusterName = $ClusterName
            LastSuccessfulTime = $firstStartTimeRecord
            LogType = $LogType
            Hostname = $Hostname
            Filename = $Filename
        }
        $firstCheckpointEntry | Select-Object OrgId, GroupId, LastSuccessfulTime, LogType, ClusterName, Hostname, Filename | Export-CSV -Path $checkpointFile -NoTypeInformation -Force
        Write-Debug "[$($LogType)]: orgId=$($OrgID);groupId=$($GroupID);clusterName=$($ClusterName);hostname=$($Hostname);filename=$($Filename);msg=New Checkpoint file created, New Checkpoint Entry Added"
        return $firstStartTimeRecord
    } else {
        [array]$checkpointImport = Import-Csv -Path $checkpointFile
        $existingEntry = $checkpointImport | Where-Object {$_.LogType -eq $LogType -and $_.OrgId -eq $OrgID -and $_.GroupId -eq $GroupID -and $_.ClusterName -eq $ClusterName -and $_.Hostname -eq $Hostname}
        if ($null -ne $existingEntry) {
            Write-Debug "[$($LogType)]: orgId=$($OrgID);groupId=$($GroupID);clusterName=$($ClusterName);hostname=$($Hostname);filename=$($Filename);msg=Last Successful Time Checkpoint Entry Found"
            return $existingEntry.LastSuccessfulTime
        } else {
            $newCheckpointEntry = [PSCustomObject]@{
                OrgId = $OrgID
                GroupId = $GroupID
                ClusterName = $ClusterName
                LastSuccessfulTime = $firstStartTimeRecord
                LogType = $LogType
                Hostname = $Hostname
                Filename = $Filename
            }
            $checkpointImport += $newCheckpointEntry
            $checkpointImport | Select-Object OrgId, GroupId, LastSuccessfulTime, LogType, ClusterName, Hostname, Filename | Export-CSV -Path $checkpointFile -NoTypeInformation -Force
            Write-Debug "[$($LogType)]: orgId=$($OrgID);groupId=$($GroupID);clusterName=$($ClusterName);hostname=$($Hostname);filename=$($Filename);msg=New Checkpoint Entry Added"
            return $firstStartTimeRecord
        }
    }
}

# Function to update the checkpoint time with the last successful API call end time
function UpdateCheckpointTime ($LogType, $LastSuccessfulTime, $OrgID = "", $GroupID = "", $ClusterName = "", $Hostname = "", $Filename = "") {

    [array]$checkpointFileImport = Import-Csv -Path $checkpointFile
    $checkpointEntry = $checkpointFileImport | Where-Object {$_.LogType -eq $LogType -and $_.OrgId -eq $OrgID -and $_.GroupId -eq $GroupID -and $_.ClusterName -eq $ClusterName -and $_.Hostname -eq $Hostname -and $_.Filename -eq $Filename}
    $checkpointEntry.LastSuccessfulTime = $LastSuccessfulTime
    $checkpointFileImport | Select-Object OrgId, GroupId, LastSuccessfulTime, LogType, ClusterName, Hostname, Filename | Export-CSV -Path $checkpointFile -NoTypeInformation -Force
}
# Function to track how many API calls were executed for each Project/Group
function ApiRateLimitTracking ($GroupID) {

    $counter = $global:apiRequestCounter | Where-Object {$_.projectId -eq $GroupID} 
    if ($null -ne $counter){
        $time = $counter.requestTimes += Get-Date -Format "u"
        [datetime]$previousMin = $time[$($time.Count)-1]
        $counter.apiRequestsInLastMin = ($time | Where-Object {$_ -gt $previousMin}).Count
    }
    if ($counter.apiRequestCount -gt 95 -and $counter.durationInMinutes -lt 1) {
        Write-Host "WARN: Nearing API Rate Limit for Project: $GroupID ($($apiRequestCounter.projectName), suspending requests for 20 seconds" -ForegroundColor Red
        Start-Sleep -Seconds 20
    }
}

# Function to decompress gzip MongoDB audit files
function DecompressGzip {
    Param (
        $InFile,
        $OutFile = ($InFile -replace '\.gz$','')
        )

        $fileInput = New-Object System.IO.FileStream $InFile, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
        $fileOutput = New-Object System.IO.FileStream $OutFile, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
        $gzipStream = New-Object System.IO.Compression.GzipStream $fileInput, ([IO.Compression.CompressionMode]::Decompress)
        $buffer = New-Object byte[](1024)
    while ($true) {
        $read = $gzipstream.Read($buffer, 0, 1024)
        if ($read -le 0){break}
        $fileOutput.Write($buffer, 0, $read)
        }
    $gzipStream.close()
    $fileOutput.close()
    $fileInput.close()
}

#================================== MangoDB FUNCTIONS =====================================================#

# MongoDB Atlas API Requests
function MongoDBAtlasApi ($GroupID, $OrgID, $ClusterName, $LogType, $StartTime, $EndTime) {

    $minDate = $StartTime.ToString("yyyy-MM-ddTHH:mm:ss")
    $maxDate = $EndTime.ToString("yyyy-MM-ddTHH:mm:ss")

    # Define request filters
    $filters = "includeCount=true&itemsPerPage=$responseRecordLimit&envelope=true"
    $timeRange = "minDate=$minDate&maxDate=$maxDate"
    $epochStartTime = ([DateTimeOffset]$minDate).ToUnixTimeSeconds()
    $epochEndTime = ([DateTimeOffset]$maxDate).ToUnixTimeSeconds()

    # Compile Headers
    $headers = @{
        'Content-Type' = 'application/json'
    }    

    # Define URI based on Log Type
    $uri = ""
    if ($LogType -eq "OrgEvents") {
        $uri = "$baseUrl/orgs/$OrgID/events?$filters&$timeRange"
    } elseif ($LogType -eq "ProjEvents") {
        $uri = "$baseUrl/groups/$GroupID/events?$filters&$timeRange"
    } elseif ($LogType -eq "Clusters") {
        $uri = "$baseUrl/groups/$GroupID/clusters?includeCount=true&envelope=true"
    } elseif ($LogType -eq "ClusterAccessLogs") {
        $uri = "$baseUrl/groups/$GroupID/dbAccessHistory/clusters/$($ClusterName)?envelope=true&nLogs=2000&start=$epochSTartTime&end=$epochEndTime"
    } else {
        Write-Debug "LogType parameter not found. Acceptable values: OrgEvents, ProjEvents, ClusterAccessLogs"
    }

    # API Request/Response processing with Pagination
    $responseCollection = @()
    do {
        $response = Invoke-RestMethod -Method 'GET' -Uri $uri -Credential $credentials -Headers $headers -ErrorVariable responseError
        ApiRateLimitTracking -GroupID $GroupID

        Write-Debug "[$LogType]: Invoked URI: $uri"
        if ($null -ne $response.accessLogs) {
            $responseCollection += $response.accessLogs
            Write-Debug "[$LogType]: $($response.accessLogs.Count) total record(s) added to the collection"
            $uri = $null
        } elseif ($response.status -eq 200) {
            $responseCollection += $response.content.results
            Write-Debug "[$LogType]: $($response.content.results.Count) record(s) added to the collection, $($responseCollection.Count)/$($response.content.totalCount) Total"  
            $uri = ($response.content.links | Where-Object {$_.rel -eq "next"}).href
        } else {
            $errorMessage = $responseError.Message | ConvertFrom-Json
             Write-Host "WARN: Unexpected API Response Status - $($errorMessage.error);$($errorMessage.reason);$($errorMessage.detail)" -ForegroundColor Red
            $uri = $null
        }
    } while ($null -ne $uri)

    Write-Debug "[$LogType]: $($responseCollection.Count) Total Record(s) Found (Time Range: $StartTime - $EndTime)"

    return $responseCollection
}

function DownloadAuditLogs ($GroupID, $OrgID, $Hostname, $StartTime, $EndTime, $Filename) {

    # Define request filters
    $epochStartTime = ([DateTimeOffset]$StartTime).ToUnixTimeSeconds()
    $epochEndTime = ([DateTimeOffset]$EndTime).ToUnixTimeSeconds()

    # Compile Headers
    $headers = @{'accept' = 'application/gzip'}

    # Download each audit log file
    $uri = ""
    $uri = "$baseUrl/groups/$GroupID/clusters/$Hostname/logs/$($Filename)?endDate=$epochEndTime&startDate=$epochStartTime"
    try {
        Write-Debug "[AuditLogs]: Invoked URI: $uri"
        Invoke-RestMethod -Method "GET" -Uri $uri -Headers $headers -Credential $credentials -OutFile "$auditLogDir/$Filename"
    } catch {
        Write-Debug "StatusCode:" $_.Exception.Response.StatusCode.value__ 
        Write-Debug "StatusDescription:" $_.Exception.Message
    }
}

# Process Org Events
function Process-AtlasEvents ($Events, $EventType) {

    $EventCollection = @()

    # Process each org event
    foreach ($event in $Events) {
        $obj = @{
            'AlertId' = $event.alertId               
            'AlertConfigId' = $event.alertConfigId
            'ApiKeyId' = $event.apiKeyId
            'Collection' = $event.collection
            'Created' = $event.created
            'CurrentValue' = $event.currentValue
            'CurrentValueNumber' = $event.currentValue.number
            'CurrentValueUnits' = $event.currentValue.units
            'Database' = $event.database
            'EventType' = $event.eventTypeName
            'GroupId' = $event.groupId
            'Hostname' = $event.hostname
            'EventId' = $event.id
            'InvoiceId' = $event.invoiceId
            'IsGlobalAdmin' = $event.isGlobalAdmin
            'Links' = $event.links
            'MetricName' = $event.metricName
            'OpType' = $event.opType
            'OrgId' = $event.orgId
            'PaymentId' = $event.paymentId
            'Port' = $event.port
            'PublicKey' = $event.publicKey
            'raw' = $event.raw
            'UserIpAddress' = $event.remoteAddress
            'ReplicaSetName' = $event.replicaSetName
            'ShardName' = $event.shardName
            'TargetPublicKey' = $event.targetPublicKey
            'TargetUsername' = $event.targetUsername
            'TeamId' = $event.teamId
            'UserId' = $event.userId
            'Username' = $event.username
            'WhitelistEntry' = $event.whitelistEntry
         }
         if ($EventType -eq "OrgEvents") {
            $obj.Add('Category','OrgEvents')
         } elseif ($EventType -eq "ProjectEvents") {
            $obj.Add('Category','ProjectEvents')
         }
         $EventCollection += $obj
    }

    return $EventCollection
}
# Process Cluster Access Logs
function Process-ClusterAccessLogs ($Events, $ClusterName) {

    $EventCollection = @()

    # Process each org event
    foreach ($event in $Events) {

        $obj = @{ 
        'AuthResult' = $event.authResult
        'AuthSource' = $event.authSource
        'FailureReason' = $event.failureReason
        'GroupId' = $event.groupId
        'Hostname' = $event.hostname
        'ClusterName' = $ClusterName
        'IpAddress' = $event.ipAddress
        'LogLine' = $event.LogLine
        'Timestamp' = $event.timestamp
        'Username' = $event.username
        'Category' = "ClusterAccessLogs"
        }

        $EventCollection += $obj
    }

    return $EventCollection
}

function Process-AuditLogs ($Events, $ClusterName, $Hostname, $GroupId, $Filename) {

    $EventCollection = @()

    # Process each org event
    foreach ($event in $Events) {

        $obj = @{ 
        'aType' = $event.atype
        'EventTimestamp' = $event.ts
        'LocalIpAddress' = $event.local
        'RemoteIpAddress' = $event.remote
        'Users' = $event.users
        'Roles' = $event.roles
        'Parameter' = $event.param
        'GroupId' = $GroupId
        'Hostname' = $Hostname
        'ClusterName' = $ClusterName
        'Category' = "AuditLogs"
        'Filename' = $Filename

        }

        $EventCollection += $obj
    }

    return $EventCollection
}

#================================== LOG ANALYTICS FUNCTIONS ===============================================#

# Function to create the authorization signature
function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource) {
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)
    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}

# Function to create and post the request to the Log Analytics API
function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType) {
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }
    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode
}
# Function to split JSON payloads greater than the 30MB Log Analytics API limit into chunks
function LogAnalytics-PayloadSplit ($Payload, $PayloadSize, $LogType){

    $increment = $payloadSize / 30
    $groupOf = [Math]::Floor($Payload.Count / $increment)
    Write-Debug "[$LogType]: Payload will be broken up into groupings of $groupOf records"
    
    $result = New-Object System.Collections.ArrayList

    for ($i = 0; $i -le $Payload.Count; $i += $groupOf) {
        if ($Payload.Count -eq $i)
        {
            break
        }
        $group = $i + $groupOf  
        [void]$result.add($Payload[$i..$group])
        $i++
    }

    Write-Debug "[$LogType]: Payload broken up into $($result.Count) seperate payloads" 

    return $result
}

# Process payload into JSON format, assess the payload size and POST to log analytics workspace
function LogAnalytics-DataProcessing($Payload, $LastSuccessfulTime, $LogType, $OrgID = "", $GroupID = "", $ClusterName = "", $Hostname = "", $Filename = "") {

    if ($null -ne $Payload) {

        # Convert payload to JSON
        $body = $Payload | ConvertTo-Json -Depth 3

        # Check if payload size exceeds the Log Analytics POST limit of 30 MB
        $payloadSize = [math]::Round(([System.Text.Encoding]::UTF8.GetBytes($body)).Count/1MB,4)

        if ($payloadSize -le 30) {
            Write-Debug "[$LogType]: Posting $($Payload.Count) record(s) to Log Analytics workspace: $payloadSize MB"
            $responseCode = Post-LogAnalyticsData -customerId $workspaceId `
                -sharedKey $workspaceKey `
                -body ([System.Text.Encoding]::UTF8.GetBytes($body)) `
                -logType $tableName

            if ($responseCode -ne 200) {
               Write-Host "[$LogType]: ERROR: Log Analytics POST, Status Code: $responseCode, unsuccessful." -ForegroundColor Red
            } else {
               Write-Host "[$LogType]: SUCCESS: $($Payload.Length) records posted to Log Analytics: $payloadSize MB" -ForegroundColor Green
               UpdateCheckpointTime -LogType $LogType `
                    -LastSuccessfulTime $LastSuccessfulTime`
                    -OrgID $OrgID `
                    -GroupID $GroupID `
                    -ClusterName $ClusterName `
                    -Hostname $Hostname `
                    -Filename $Filename
            }
        } else {
            Write-Debug "JSON payload execeeded Log Analytics API maximum of 30MB: Total size, $payloadSize MB. Initiating function to breakup payload..."
            $array = LogAnalytics-PayloadSplit -Payload $Payload -PayloadSize $payloadSize -LogType $LogType
            0 .. $array.Count | ForEach-Object {
                if ($null -ne $array[$_]) {
                    $json = $array[$_] | ConvertTo-Json -Depth 3
                    $newPayloadSize = [math]::Round(([System.Text.Encoding]::UTF8.GetBytes($json)).Count/1MB,4)
                    Write-Debug "[$LogType]: Posting $($array[$_].Count) record(s) to Log Analytics workspace: $newPayloadSize MB"
                    $responseCode = Post-LogAnalyticsData -customerId $workspaceId `
                        -sharedKey $workspaceKey `
                        -body ([System.Text.Encoding]::UTF8.GetBytes($body)) `
                        -logType $tableName
                    if ($responseCode -ne 200){
                       Write-Host "[$LogType]: ERROR: Log Analytics POST, Status Code: $responseCode, unsuccessful." -ForegroundColor Red
                    } else {
                       Write-Host "[$LogType]: SUCCESS: $($array[$_].Count) records posted to Log Analytics: $newpayloadSize MB" -ForegroundColor Green
                       UpdateCheckpointTime -LogType $LogType `
                            -LastSuccessfulTime $LastSuccessfulTime `
                            -OrgID $OrgID `
                            -GroupID $GroupID `
                            -ClusterName $ClusterName `
                            -Hostname $Hostname `
                            -Filename $Filename
                    }
                }
            }
        }
    }
}

#====================================== MAIN SCRIPT ========================================================#

# Start Processing Marker
$stopWatch = [system.diagnostics.stopwatch]::StartNew()

# - - - - - - - - - - - - - - - - - - - ORG EVENTS - - - - - - - - - - - - - - - - - - - - - - -#

# Identify all Organization Ids
$allOrgs = Invoke-RestMethod -Method "GET" -Uri "https://cloud.mongodb.com/api/atlas/v1.0/orgs?includeCount=true&envelope=true" -Credential $credentials
$orgIds = $allOrgs.content.results.id
Write-Debug "[Orgs]: $($orgIds.Count) Org(s) Found"

# Retrieve all Organization Events
foreach ($org in $orgIds) {

    # Determine Time Interval for API request
    [datetime]$startTimeOrgEvents = GetStartTime -EndTime $endTime `
        -OrgId $org `
        -LogType "OrgEvents"

    # Retreive all Org Events
    $allOrgEvents = MongoDBAtlasApi -OrgID $org `
        -StartTime $startTimeOrgEvents `
        -EndTime $endTime `
        -LogType "OrgEvents"
    
    if ($allOrgEvents.Count -ne 0) {

        # Process all Org Events
        $OrgEvents = Process-AtlasEvents -Events $allOrgEvents -EventType "OrgEvents"

        # Post to Log Analytics workspace
        LogAnalytics-DataProcessing -LastSuccessfulTime $endTime `
            -OrgId $org `
            -Payload $OrgEvents `
            -LogType "OrgEvents"

    } else {
        Write-Debug "[OrgEvents]: No records found and processed for orgId=$org"
    }
}

# - - - - - - - - - - - - - - - - - - - PROJECT EVENTS - - - - - - - - - - - - - - - - - - - - - - -#

# Identify all Project (Group) Ids
$allProjs = Invoke-RestMethod -Method "GET" -Uri "$baseUrl/groups?includeCount=true&envelope=true" -Credential $credentials
Write-Debug "[Projs]: $($allProjs.content.results.id.Count) Project(s) Found"
$allClusters = @()

# Retrieve all Project Events
foreach ($proj in $allProjs.content.results) {

    # Retrieve checkpoint time
    [DateTime]$startTimeProjEvents = GetStartTime -EndTime $endTime `
        -OrgId $proj.orgId `
        -GroupID $proj.id `
        -LogType "ProjEvents"

    # Add record to track API request per project
    $newCounterObj = [hashtable]@{
        projectId = $proj.id
        projectName = $proj.name
        requestTimes = @()
        apiRequestsInLastMin = 0
    }
    $apiRequestCounter += $newCounterObj

    # Identify all Clusters within the project
    $projClusters = Invoke-RestMethod -Method "GET" `
        -Uri "$baseUrl/groups/$($proj.id)/clusters?includeCount=true&envelope=true" `
        -Credential $credentials

    $clusters = $projClusters.content.results
    Write-Debug "[Clusters]: $($clusters.Count) Cluster(s) Found in Project $($proj.id) ($($proj.name)) "
    $allClusters += $clusters 

    # Request all Project Events
    Write-Debug "[ProjEvents]: Processing Project Events for $($proj.id) ($($proj.name))"
    $allProjEvents = MongoDBAtlasApi -GroupID $proj.id `
        -StartTime $startTimeProjEvents `
        -EndTime $endTime `
        -LogType "ProjEvents"

    if ($allProjEvents.Count -ne 0) {

        # Process all Project Events
        $ProjEvents = Process-AtlasEvents -Events $allProjEvents -LogType "ProjEvents"

        # Post to Log Analytics workspace
        LogAnalytics-DataProcessing -LastSuccessfulTime $endTime `
            -OrgId $proj.orgId `
            -GroupID $proj.id `
            -Payload $ProjEvents `
            -LogType "ProjEvents"

    } else {
        Write-Debug "[ProjEvents]: No records found and processed for $($proj.id) ($($proj.name))"
    }
}

# - - - - - - - - - - - - - - - - - - - CLUSTER ACCESS LOGS - - - - - - - - - - - - - - - - - - - - - - -#
$clusterHostnames = @()

foreach ($cluster in $allClusters) {
    
    # Retrieve checkpoint time
    [DateTime]$startTimeClusterAccessLogs = GetStartTime -EndTime $endTime `
        -ClusterName $cluster.name `
        -GroupID $cluster.groupId `
        -LogType "ClusterAccessLogs"

    # Request all Cluster Access Logs
    Write-Debug "[ClusterAccessLogs]: Processing Cluster Access Logs for $($cluster.name)"
    $allClusterAccessLogs = MongoDBAtlasApi -GroupID $cluster.groupId `
        -ClusterName $cluster.name `
        -StartTime $startTimeClusterAccessLogs `
        -EndTime $endTime `
        -LogType "ClusterAccessLogs"

        if ($allClusterAccessLogs.Count -ne 0) {

            # Process all Cluster Access Logs
            $ClusterAccessLogs = Process-ClusterAccessLogs -Events $allClusterAccessLogs -ClusterName $cluster.name
    
            # Post to Log Analytics workspace
            LogAnalytics-DataProcessing -LastSuccessfulTime $endTime `
                -ClusterName $cluster.name `
                -GroupID $cluster.groupId `
                -Payload $ClusterAccessLogs `
                -LogType "ClusterAccessLogs" 
    
        } else {
        Write-Debug "[ClusterAccessLogs]: No records found and processed for $($cluster.name)"
    }

    # Parse all hostnames from each cluster, utilized to retrieve audit logs
    $hosturis = $cluster.mongoURI -split ','
    foreach ($hosturi in $hosturis) {
        $parse = [regex]::Match($hosturi, '^(mongodb://)?([^:]+)\:')
        $obj = @{'hostname' = $parse.Groups[2].Value
                'groupId' = $cluster.groupId
                'clusterName' = $cluster.name}
        $clusterHostnames += $obj 
    }
}
# - - - - - - - - - - - - - - - - - - - AUDIT LOGS  - - - - - - - - - - - - - - - - - - - - - - - - - - - - #

# Define audit log types
$global:auditLogTypes = @(
    'mongodb-audit-log.gz',
    'mongos-audit-log.gz'
)

foreach ($hostname in $clusterHostnames) {

    # Decompress all audit files and delete compressed files
    foreach ($file in $logFilenames) {

    # Retrieve checkpoint time
    [DateTime]$startTimeAuditLog = GetStartTime -LogType "AuditLogs" `
        -EndTime $endTime `
        -GroupID $hostname.groupId `
        -ClusterName $hostname.clusterName `
        -Hostname $hostname.hostname `
        -Filename $file.Name 

    # Download all audit files
    DownloadAuditLogs -GroupID $hostname.groupId `
        -Hostname $hostname.hostname `
        -StartTime $startTimeAuditLog `
        -EndTime $endTime `
        -Filename $file.Name

    # Get List of Audit Logs Filenames
    $logFilenames = Get-ChildItem -Path "$auditLogDir/" -Filter *.gz

        # Decompress gzip file and save locally as a json
        DecompressGzip -InFile "$auditLogDir/$($file.Name)" -OutFile "$auditLogDir/$($file.BaseName).json" 
         
        # Retreive decompressed Audit log (json) contents
        $rawAuditLogs = Get-Content -Path "$auditLogDir/$($file.BaseName).json" | ConvertFrom-Json
        Write-Debug "[AuditLogs]: hostname=$($hostname.hostname);file=$($file.Name);msg=$($rawAuditLogs.Count) Audit events found"

        # Process and normalized Audit Logs
        if ($rawAuditLogs.Count -ne 0){
            $processedAuditLogs = Process-AuditLogs -Events $rawAuditLogs `
                -GroupId $hostname.groupId `
                -ClusterName $hostname.clusterName `
                -Hostname $hostname.hostname `
                -Filename $file.Name
        } else {
            Write-Debug "[AuditLogs]: hostname=$($hostname.hostname);filename=$($file.Name);msg=No records found or processed"
            $processedAuditLogs = $null

        }
        # Delete locally saved audit files
        Remove-Item "$auditLogDir/$($file.BaseName).*"

        # Process all Audit logs and post to Log Analytics workspace
        if ($processedAuditLogs.Count -ne 0) {
            LogAnalytics-DataProcessing -LastSuccessfulTime $endTime `
                -ClusterName $hostname.clusterName `
                -GroupID $hostname.groupId `
                -Hostname $hostname.hostname `
                -Filename $file.Name `
                -Payload $processedAuditLogs `
                -LogType "AuditLogs" 
        } else {
            Write-Debug "[AuditLogs]: No audit log events were found for all cluster hosts"
        }
    }
}


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - #

$requestCounts = $apiRequestCounter | Select-Object projectId, apiRequestsInLastMin | Out-String
Write-Debug $requestCounts

# End Processing Marker
$stopWatch.Stop()
$executionTime = [math]::Round($($stopWatch.Elapsed.TotalMinutes),2)
Write-Debug "Total execution time: $($executionTime) Minutes"


# Write an information log with the current time.
Write-Host "PowerShell timer trigger function ran! TIME: $currentUTCtime"
#============================================ END SCRIPT =========================================================#
