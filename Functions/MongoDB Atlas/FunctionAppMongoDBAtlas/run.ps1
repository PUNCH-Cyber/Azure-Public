<#
    TITLE:          MongoDB Atlas Data Connector for Microsoft Sentinel
    VERSION:        1.0
    LAST MODIFIED:  01/07/2022
    AUTHOR:         @punchcyber.com
    
    DESCRIPTION:
    The following data connector retrieves the following log types from MongoDB Atlas API, transforms the data and pushes to the Log Ananlytics workspace for consumption by Microsoft Sentinel:
        * Org Events                https://docs.atlas.mongodb.com/reference/api/events-orgs-get-all/
        * Project Events            https://docs.atlas.mongodb.com/reference/api/events-projects-get-all/
        * Audit Logs                https://docs.atlas.mongodb.com/reference/api/logs/
        * Cluster Access Logs       https://docs.atlas.mongodb.com/reference/api/access-tracking-get-database-history-clustername/ 

    REQUIRED VARIABLES:
        * debug - (true/false) verbose logging toggle
        * publicKey - MongoDB API username/public key
        * priaveKey - MongoDB API password/private key
        * timeInterval - initial log event lookback timeframe (in minutes)
        * workspaceId - Log Analytics workspace Id
        * workspaceKey - Log Analytics workspace key
    
    MONGODB ATLAS API LIMITATIONS:
        * 100 API requests per minute, per Project
        * Maximum records per API response is 500
        * Cluster Access Logs: a) maximum record is set to 2000, no header info is returned in the API response, this information would provide any pagningation information, any records past 2000 events will be lost.

    
#>
# Input bindings are passed in via param block.
param ($Timer)

# Get the current universal time in the default string format.
$currentUTCtime = (Get-Date).ToUniversalTime()

# The 'IsPastDue' property is 'true' when the current function invocation is later than scheduled.
if ($Timer.IsPastDue) {
    Write-Host "PowerShell timer is running late!"
}

################################################################################################
# VARIABLES 
################################################################################################

# DEBUG - Verbose logging toggle
if ($env:debug -eq $true) {
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
# Define the number of events per API response, limits: up to 500. Lower the record limit risks API request limitations. This limit does not apply to Audit Logs
$global:responseRecordLimit = 500
$global:apiRequestCounter = @()
# Define audit log types
$global:auditLogTypes = @(
    'mongodb-audit-log',
    'mongodb'
)

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
$global:auditLogDirectory = "$($cwd)home\LogFiles\"

################################################################################################
# GENERAL FUNCTIONS
################################################################################################

# Function to retrieve the checkpoint start time of the last successful API call for a given logtype. Checkpoint file will be created if none exists.
function GetStartTime ($LogType, $EndTime, $OrgID = "", $GroupID = "", $ClusterName = "", $Hostname = "", $Filename = "", $AtlasRespStatus = "", $PostRespStatus = "") {

    $firstStartTimeRecord = $EndTime.AddMinutes(-$global:timeInterval)

    if ([System.IO.File]::Exists($global:checkpointFile) -eq $false) {
        $firstCheckpointEntry = [PSCustomObject]@{ 
            OrgId = $OrgID
            GroupId = $GroupID
            ClusterName = $ClusterName
            LastSuccessfulTime = $firstStartTimeRecord
            LogType = $LogType
            Hostname = $Hostname
            Filename = $Filename
            AtlasRespStatus = $AtlasRespStatus
            PostRespStatus = $PostRespStatus

        }
        $firstCheckpointEntry | Select-Object OrgId, GroupId, LastSuccessfulTime, LogType, ClusterName, Hostname, Filename, AtlasRespStatus, PostRespStatus | Export-CSV -Path $global:checkpointFile -NoTypeInformation -Force
        
        Write-Debug "[$($LogType)]: orgId=$($OrgID);groupId=$($GroupID);clusterName=$($ClusterName);hostname=$($Hostname);filename=$($Filename);msg=New Checkpoint file created, New Checkpoint Entry Added"

        return $firstStartTimeRecord

    } else {
        [array]$checkpointImport = Import-Csv -Path $global:checkpointFile
        $existingEntry = $checkpointImport | Where-Object {($_.LogType -eq $LogType) -and ($_.OrgId -match $OrgID) -and ($_.GroupId -match $GroupID) -and ($_.ClusterName -match $ClusterName) -and ($_.Hostname -eq $Hostname) -and ($_.Filename -eq $Filename)}

        if ($null -ne $existingEntry) {
            Write-Debug "[$($LogType)]: orgId=$($OrgID);groupId=$($GroupID);clusterName=$($ClusterName);hostname=$($Hostname);filename=$($Filename);msg=Last Successful Time Checkpoint Entry Found"

            return [datetime]$existingEntry.LastSuccessfulTime

        } else {
            $newCheckpointEntry = [PSCustomObject]@{
                OrgId = $OrgID
                GroupId = $GroupID
                ClusterName = $ClusterName
                LastSuccessfulTime = $firstStartTimeRecord
                LogType = $LogType
                Hostname = $Hostname
                Filename = $Filename
                AtlasRespStatus = $AtlasRespStatus
                PostRespStatus = $PostRespStatus
            }

            $checkpointImport += $newCheckpointEntry
            $checkpointImport | Select-Object OrgId, GroupId, LastSuccessfulTime, LogType, ClusterName, Hostname, Filename, AtlasRespStatus, PostRespStatus | Export-CSV -Path $global:checkpointFile -NoTypeInformation -Force
            Write-Debug "[$($LogType)]: orgId=$($OrgID);groupId=$($GroupID);clusterName=$($ClusterName);hostname=$($Hostname);filename=$($Filename);msg=New Checkpoint Entry Added"
            return $firstStartTimeRecord
        }
    }

}

# Function to update the checkpoint time with the last successful API call end time
function UpdateCheckpointEntry ($LogType, $LastSuccessfulTime = "", $OrgID = "", $GroupID = "", $ClusterName = "", $Hostname = "", $Filename = "", $AtlasRespStatus = "", $PostRespStatus = "") {

    [array]$checkpointFileImport = Import-Csv -Path $global:checkpointFile

    $checkpointEntry = $checkpointFileImport | Where-Object {($_.LogType -eq $LogType) -and ($_.OrgId -match $OrgID) -and ($_.GroupId -match $GroupID) -and ($_.ClusterName -match $ClusterName) -and ($_.Hostname -eq $Hostname) -and ($_.Filename -eq $Filename)}

    # Update the status of the Atlast API request
    if ($AtlasRespStatus -ne ""){
        $checkpointEntry.AtlasRespStatus = $AtlasRespStatus
    }

    # Update the Last Successful time if there was a successful Atlas API request and successful post to Log Analytics
    if (($checkpointEntry.AtlasRespStatus -eq "Success") -and ($PostRespStatus -eq "Success")) {
        $checkpointEntry.LastSuccessfulTime = $LastSuccessfulTime
        $checkpointEntry.PostRespStatus = "Success"
    } elseif (($checkpointEntry.AtlasRespStatus -eq "Failed") -and ($PostRespStatus -eq "Success")) {
        $checkpointEntry.PostRespStatus = "Failed"
    } elseif ($PostRespStatus -eq "Failed") {
        $checkpointEntry.PostRespStatus = "Failed"
    }

    $checkpointFileImport | Select-Object OrgId, GroupId, LastSuccessfulTime, LogType, ClusterName, Hostname, Filename, AtlasRespStatus, PostRespStatus | Export-CSV -Path $global:checkpointFile -NoTypeInformation -Force

}

# Function to track how many API calls were executed for each Group (Project) ID
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

# Function to decompress gzip files
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

################################################################################################
# MONGODB ATLAS FUNCTIONS
################################################################################################

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
        $uri = "$global:baseUrl/orgs/$OrgID/events?$filters&$timeRange"
    } elseif ($LogType -eq "ProjEvents") {
        $uri = "$global:baseUrl/groups/$GroupID/events?$filters&$timeRange"
    } elseif ($LogType -eq "Clusters") {
        $uri = "$global:baseUrl/groups/$GroupID/clusters?includeCount=true&envelope=true"
    } elseif ($LogType -eq "ClusterAccessLogs") {
        $uri = "$global:baseUrl/groups/$GroupID/dbAccessHistory/clusters/$($ClusterName)?envelope=true&nLogs=2000&start=$epochSTartTime&end=$epochEndTime"
    } else {
        Write-Debug "LogType parameter not valid. Acceptable values: OrgEvents, ProjEvents, ClusterAccessLogs"
    }

    # API Request/Response processing with Pagination
    $responseCollection = @()
    do {

        $response = Invoke-RestMethod -Method 'GET' -Uri $uri -Credential $global:credentials -Headers $headers -ErrorVariable responseError
        ApiRateLimitTracking -GroupID $GroupID

        Write-Debug "[$LogType]: Invoking URI: $uri"
        # Cluster Access Logs will return an accessLogs parameter
        if ($null -ne $response.accessLogs) {
            $responseCollection += $response.accessLogs
            Write-Debug "[$LogType]: $($response.accessLogs.Count) total record(s) added to the collection"
            UpdateCheckpointEntry -LogType $LogType `
                -OrgID $OrgID `
                -GroupID $GroupID `
                -ClusterName $ClusterName `
                -AtlasRespStatus "Success"
            $uri = $null
        } elseif ($response.status -eq 200) {
            $responseCollection += $response.content.results
            Write-Debug "[$LogType]: $($response.content.results.Count) record(s) added to the collection, $($responseCollection.Count)/$($response.content.totalCount) Total"  
            $uri = ($response.content.links | Where-Object {$_.rel -eq "next"}).href
            UpdateCheckpointEntry -LogType $LogType `
                -OrgID $OrgID `
                -GroupID $GroupID `
                -ClusterName $ClusterName `
                -AtlasRespStatus "Success"
        } else {
            $errorMessage = $responseError.Message | ConvertFrom-Json
             Write-Host "WARN: Unexpected API Response Status - $($errorMessage.error);$($errorMessage.reason);$($errorMessage.detail)" -ForegroundColor Red
             UpdateCheckpointEntry -LogType $LogType `
                -OrgID $OrgID `
                -GroupID $GroupID `
                -ClusterName $ClusterName `
                -AtlasRespStatus "Failed"
            $uri = $null
        }
    } while ($null -ne $uri)

    Write-Debug "[$LogType]: $($responseCollection.Count) Total Record(s) Found (Time Range: $StartTime - $EndTime)"
    return $responseCollection

}

# Function to request and download Audit Logs from MongoDB Atlas API and save it locally to the file directory as a gzip package
function DownloadAuditLogs ($GroupID, $Hostname, $StartTime, $EndTime, $Filename) {

    # Define request filters
    $epochStartTime = ([DateTimeOffset]$StartTime).ToUnixTimeSeconds()
    $epochEndTime = ([DateTimeOffset]$EndTime).ToUnixTimeSeconds()

    # Compile Headers
    $headers = @{'accept' = 'application/gzip'}

    # Download each audit log file
    $uri = "$global:baseUrl/groups/$GroupID/clusters/$Hostname/logs/$($Filename).gz?endDate=$epochEndTime&startDate=$epochStartTime"
    Write-Debug "[AuditLogs]: Invoking URI: $uri"

    try {
        Invoke-RestMethod -Method "GET" -Uri $uri -Headers $headers -Credential $global:credentials -OutFile "$auditLogDirectory/$Filename.gz" -ErrorVariable responseError -ErrorAction SilentlyContinue
        ApiRateLimitTracking -GroupID $GroupID
    } catch {
        $errorMessage = $responseError.Message | ConvertFrom-Json
        Write-Debug "[AuditLogs]: ERROR: Unexpected API Response Status: $($errorMessage.error);$($errorMessage.reason);$($errorMessage.detail)"  
    }

    if ($null -ne $errorMessage) {
        UpdateCheckpointEntry -LogType "AuditLogs" `
            -GroupID $GroupID `
            -ClusterName $ClusterName `
            -Hostname $Hostname `
            -Filename $Filename `
            -AtlasRespStatus "Failed"
    } else {
        Write-Debug "[AuditLogs]: hostname=$($Hostname);filename=$($Filename);msg=Audit File downloaded successfully (Time Range: $StartTime - $EndTime)"
        UpdateCheckpointEntry -LogType "AuditLogs" `
            -GroupID $GroupID `
            -ClusterName $ClusterName `
            -Hostname $Hostname `
            -Filename $Filename `
            -AtlasRespStatus "Success"
    }

}

# Function to process, transform and normalize Org and Project Events
function Process-AtlasEvents ($Events, $EventType) {

    $EventCollection = @()
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

# Function to process, transform and normalize Cluster Access Logs
function Process-ClusterAccessLogs ($Events, $ClusterName) {

    $EventCollection = @()
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
# Function to process, transform and normalize Audit Logs
function Process-AuditLogs ($Events, $ClusterName, $Hostname, $GroupId, $Filename) {

    $EventCollection = @()
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

################################################################################################
# LOG ANALYTICS FUNCTIONS
################################################################################################

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

    try {
        $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing -ErrorVariable responseError
    } catch {
        $errorMessage = $responseError.Message | ConvertFrom-Json
        Write-Debug "[Log Analytics]: ERROR: Unexpected API Response: $($errorMessage.error);$($errorMessage.Message)"  
    }

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

        # If the payload is less than 30MB Post to Log Analytics
        if ($payloadSize -le 30) {
            Write-Debug "[$LogType]: Posting $($Payload.Count) record(s) to Log Analytics workspace: $payloadSize MB"
            $responseCode = Post-LogAnalyticsData -customerId $global:workspaceId `
                -sharedKey $global:workspaceKey `
                -body ([System.Text.Encoding]::UTF8.GetBytes($body)) `
                -logType $global:tableName

            if ($responseCode -ne 200) {
                Write-Host "[$LogType]: ERROR: Log Analytics POST, Status Code: $responseCode, unsuccessful." -ForegroundColor Red
                UpdateCheckpointEntry -LogType $LogType `
                    -OrgID $OrgID `
                    -GroupID $GroupID `
                    -ClusterName $ClusterName `
                    -Hostname $Hostname `
                    -Filename $Filename `
                    -PostRespStatus "Failed"
            } else {
                Write-Host "[$LogType]: SUCCESS: $($Payload.Length) records posted to Log Analytics: $payloadSize MB" -ForegroundColor Green
                UpdateCheckpointEntry -LogType $LogType `
                    -LastSuccessfulTime $LastSuccessfulTime `
                    -OrgID $OrgID `
                    -GroupID $GroupID `
                    -ClusterName $ClusterName `
                    -Hostname $Hostname `
                    -Filename $Filename `
                    -PostRespStatus "Success"
            }
        } else {
            # If the payload exceeds 30MB, split the payload into chunks and post to Log Analytics
            Write-Debug "JSON payload execeeded Log Analytics API maximum of 30MB: Total size, $payloadSize MB. Initiating function to breakup payload..."
            $array = LogAnalytics-PayloadSplit -Payload $Payload -PayloadSize $payloadSize -LogType $LogType

            0 .. $array.Count | ForEach-Object {

                if ($null -ne $array[$_]) {
                    $json = $array[$_] | ConvertTo-Json -Depth 3
                    $newPayloadSize = [math]::Round(([System.Text.Encoding]::UTF8.GetBytes($json)).Count/1MB,4)
                    Write-Debug "[$LogType]: Posting $($array[$_].Count) record(s) to Log Analytics workspace: $newPayloadSize MB"
                    $responseCode = Post-LogAnalyticsData -customerId $global:workspaceId `
                        -sharedKey $global:workspaceKey `
                        -body ([System.Text.Encoding]::UTF8.GetBytes($body)) `
                        -logType $global:tableName

                    if ($responseCode -ne 200){
                        Write-Host "[$LogType]: ERROR: Log Analytics POST, Status Code: $responseCode, unsuccessful." -ForegroundColor Red
                        UpdateCheckpointEntry -LogType $LogType `
                            -OrgID $OrgID `
                            -GroupID $GroupID `
                            -ClusterName $ClusterName `
                            -Hostname $Hostname `
                            -Filename $Filename `
                            -PostRespStatus "Failed"
                    } else {
                        Write-Host "[$LogType]: SUCCESS: $($array[$_].Count) records posted to Log Analytics: $newpayloadSize MB" -ForegroundColor Green
                        UpdateCheckpointEntry -LogType $LogType `
                            -LastSuccessfulTime $LastSuccessfulTime `
                            -OrgID $OrgID `
                            -GroupID $GroupID `
                            -ClusterName $ClusterName `
                            -Hostname $Hostname `
                            -Filename $Filename `
                            -PostRespStatus "Success"
                   }
                }
            }
        }
    } else {
        Write-Debug "[$LogType]: orgId=$($OrgID);groupId=$($GroupID);clusterName=$($ClusterName);hostname=$($Hostname);filename=$($Filename);msg=No records were found, processed or posted to the Log Analytics workspace"
        UpdateCheckpointEntry -LogType $LogType `
            -LastSuccessfulTime $LastSuccessfulTime `
            -OrgID $OrgID `
            -GroupID $GroupID `
            -ClusterName $ClusterName `
            -Hostname $Hostname `
            -Filename $Filename `
            -PostRespStatus "Success"
    }
}        

################################################################################################
# MAIN SCRIPT
################################################################################################

# Start Processing Marker
$stopWatch = [system.diagnostics.stopwatch]::StartNew()

# - - - - - - - - - - - - - - - - - - - ORG EVENTS - - - - - - - - - - - - - - - - - - - - - - -#

# Identify all Organization Ids
$allOrgs = Invoke-RestMethod -Method "GET" -Uri "https://cloud.mongodb.com/api/atlas/v1.0/orgs?includeCount=true&envelope=true" -Credential $global:credentials
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
    
    # Process, transform, and normalize Org Events
    $OrgEvents = Process-AtlasEvents -Events $allOrgEvents -EventType "OrgEvents"

    # Pre-post processing and validation then post to Log Analytics workspace
    LogAnalytics-DataProcessing -LastSuccessfulTime $endTime `
        -OrgId $org `
        -Payload $OrgEvents `
        -LogType "OrgEvents"
}

# - - - - - - - - - - - - - - - - - PROJECT EVENTS - - - - - - - - - - - - - - - - - - - - - - -#

# Identify all Project (Group) Ids
$allProjs = Invoke-RestMethod -Method "GET" -Uri "$global:baseUrl/groups?includeCount=true&envelope=true" -Credential $global:credentials
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
        -Uri "$global:baseUrl/groups/$($proj.id)/clusters?includeCount=true&envelope=true" `
        -Credential $global:credentials
    $clusters = $projClusters.content.results
    Write-Debug "[Clusters]: $($clusters.Count) Cluster(s) Found in Project $($proj.id) ($($proj.name)) "
    $allClusters += $clusters 

    # Request all Project Events
    Write-Debug "[ProjEvents]: Processing Project Events for $($proj.id) ($($proj.name))"
    $allProjEvents = MongoDBAtlasApi -GroupID $proj.id `
        -StartTime $startTimeProjEvents `
        -EndTime $endTime `
        -LogType "ProjEvents"

    # Process, transform, and normalize Project Events
    $ProjEvents = Process-AtlasEvents -Events $allProjEvents -LogType "ProjEvents"

    # Pre-post processing and validation then post to Log Analytics workspace
    LogAnalytics-DataProcessing -LastSuccessfulTime $endTime `
        -OrgId $proj.orgId `
        -GroupID $proj.id `
        -Payload $ProjEvents `
        -LogType "ProjEvents"

}

# - - - - - - - - - -  - - - - - - - CLUSTER ACCESS LOGS - - - - - - - - - - - - - - - - - - - - -#
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

    # Process, transform, and normalize all Cluster Access Logs
    $ClusterAccessLogs = Process-ClusterAccessLogs -Events $allClusterAccessLogs -ClusterName $cluster.name

    # Pre-post processing and validation then post to Log Analytics workspace
    LogAnalytics-DataProcessing -LastSuccessfulTime $endTime `
        -ClusterName $cluster.name `
        -GroupID $cluster.groupId `
        -Payload $ClusterAccessLogs `
        -LogType "ClusterAccessLogs" 

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

foreach ($hostname in $clusterHostnames) {

    # Decompress each audit file for the current host in the cluster and post to Log Analuytics
    foreach ($file in $global:auditLogTypes) {

    # Retrieve checkpoint time
    [DateTime]$startTimeAuditLog = GetStartTime -LogType "AuditLogs" `
        -EndTime $endTime `
        -GroupID $hostname.groupId `
        -ClusterName $hostname.clusterName `
        -Hostname $hostname.hostname `
        -Filename $file

    # Download Audit File from Atlas API
    DownloadAuditLogs -GroupID $hostname.groupId `
        -Hostname $hostname.hostname `
        -StartTime $startTimeAuditLog `
        -EndTime $endTime `
        -Filename $file

    if ([System.IO.File]::Exists("$auditLogDirectory/$($file).gz") -eq $true) {
        # Decompress gzip file and save locally as a json
        DecompressGzip -InFile "$auditLogDirectory/$($file).gz" -OutFile "$auditLogDirectory/$($file).json" 
            
        # Retreive decompressed Audit log (json) contents
        $rawAuditLogs = Get-Content -Path "$auditLogDirectory/$($file).json" | ConvertFrom-Json
        Write-Debug "[AuditLogs]: hostname=$($hostname.hostname);filename=$($file);msg=$($rawAuditLogs.Count) Audit events found"

        # Process, transform, and normalize Audit Logs
        $processedAuditLogs = Process-AuditLogs -Events $rawAuditLogs `
            -GroupId $hostname.groupId `
            -ClusterName $hostname.clusterName `
            -Hostname $hostname.hostname `
            -Filename $file
    } else {
        # If the json file does not exist, it is an indication the file was not downloaded successfully from the Atlas API and decompressed
        $processedAuditLogs = $null
    }

    # Pre-post processing and validation then post to Log Analytics workspace
    LogAnalytics-DataProcessing -LastSuccessfulTime $endTime `
            -ClusterName $hostname.clusterName `
            -GroupID $hostname.groupId `
            -Hostname $hostname.hostname `
            -Filename $file `
            -Payload $processedAuditLogs `
            -LogType "AuditLogs" 

        # Delete locally saved audit files
        Remove-Item "$auditLogDirectory/*" -Force
    }
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - #

# Calculate total API requests per minute per Group (Project) ID
$requestCounts = $apiRequestCounter | Select-Object projectId, apiRequestsInLastMin | Out-String
Write-Debug $requestCounts

# End Processing Marker
$stopWatch.Stop()
$executionTime = [math]::Round($($stopWatch.Elapsed.TotalMinutes),2)
Write-Debug "Total execution time: $($executionTime) Minutes"

# Write an information log with the current time.
Write-Host "PowerShell timer trigger function ran! TIME: $currentUTCtime"

################################################################################################
# END SCRIPT
################################################################################################
