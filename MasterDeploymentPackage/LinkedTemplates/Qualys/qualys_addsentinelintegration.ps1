
param(
    [string] [Parameter(Mandatory=$true)] $workspaceId,
    [string] [Parameter(Mandatory=$true)] $workspaceKey,
    [string] [Parameter(Mandatory=$true)] $qualysInstanceURL,
    [string] [Parameter(Mandatory=$true)] $qualysAuthInfo,
    [string] [Parameter(Mandatory=$true)] $integrationName,
    [string] [Parameter(Mandatory=$true)] $sentinelTableName
)
## Get Current Integration Settings
function GetIntegrationSettings {

    param(
        [string] [Parameter(Mandatory=$true)] $QualysInstanceURL,
        [hashtable] [Parameter(Mandatory=$true)] $Headers
    )

    $getUri = "$QualysInstanceURL/qps/rest/2.0/get/integration/azure/sentinel/vm"
    $getResponse = Invoke-RestMethod -Uri $getUri -Method "GET" -Headers $Headers

    if ($getResponse.ServiceResponse.responseCode -eq "SUCCESS"){
        Write-Host "Integration Settings:" $getResponse.ServiceResponse.data
    }
    else{
        Write-Host "StatusCode:" $getResponse.ServiceResponse.responseCode
        Write-Host "StatusDescription:" $getResponse.ServiceResponse.responseErrorDetails.errorMessage
        Write-Host "Resolution:" $getResponse.ServiceResponse.responseErrorDetails.errorResolution
    }
}

## Add Azure Sentinel Integration Settings
function AddSentinelIntegration {

    param(
        [string] [Parameter(Mandatory=$true)] $QualysInstanceURL,
        [hashtable] [Parameter(Mandatory=$true)] $Headers,
        [string] [Parameter(Mandatory=$true)] $WorkspaceId,
        [string] [Parameter(Mandatory=$true)] $WorkspaceKey,
        [string] [Parameter(Mandatory=$true)] $SentinelTableName,
        [string] [Parameter(Mandatory=$true)] $IntegrationName
    )

    $Uri = "$QualysInstanceURL/qps/rest/2.0/get/integration/azure/sentinel/vm"
    $json = @{
        workspaceId = $WorkspaceId
        primaryKey = $WorkspaceKey
        minSeverity = 3
        baseCategory = "IG"
        customLogName = $SentinelTableName
        name = $IntegrationName
        resultSectionNeeded = false
        apiVersion = "2016-04-01"
    }
    $body = $json | ConvertTo-Json

    $response = Invoke-RestMethod -Uri $Uri -Method "POST" -Headers $Headers -Body $body

    if ($response.ServiceResponse.responseCode -eq "SUCCESS"){
        Write-Host "Integration settings applied successfully:" $response.ServiceResponse.data
    }
    else{
        Write-Host "Integration settings applied unsuccessfully:"
        Write-Host "StatusCode:" $response.ServiceResponse.responseCode
        Write-Host "StatusDescription:" $response.ServiceResponse.responseErrorDetails.errorMessage
        Write-Host "Resolution:" $response.ServiceResponse.responseErrorDetails.errorResolution
    }

}

## Main Script
$headers = @{"Authorization" = "Basic $($qualysAuthInfo)"}

## Get Current Integration Settings
GetIntegrationSettings -QualysInstanceURL $qualysInstanceURL -Headers $headers 

## Add Integration Settings
AddSentinelIntegration -QualysInstanceURL $qualysInstanceURL `
                        -WorkspaceId $workspaceId `
                        -WorkspaceKey $workspaceKey `
                        -SentinelTableName $sentinelTableName `
                        -IntegrationName $integrationName `
                        -Headers $headers

# # Get Subsquent Integration Settings
GetIntegrationSettings -QualysInstanceURL $qualysInstanceURL -Headers $headers