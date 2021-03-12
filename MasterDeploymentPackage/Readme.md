
[![Deploy To Azure](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.svg?sanitize=true)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw%2Egithubusercontent%2Ecom%2FPUNCH%2DCyber%2FAzure%2DPublic%2Fmain%2FMasterDeploymentPackage%2FAzureMasterDeployment%2Ejson/createUIDefinitionUri/https%3A%2F%2Fraw%2Egithubusercontent%2Ecom%2FPUNCH%2DCyber%2FAzure%2DPublic%2Fmain%2FMasterDeploymentPackage%2FCustomUITemplate%2Ejson)

### Deployment Notes:
This template will deploy the following resources in order:
 - Resource Groups "...-Sentinel", "...-Ingestion", "...-Resources"
 - Log Analytics Workspace (Dependent on "...-Sentinel" RG)
 - SecurityInsights Solution to LA Workspace (Dependent on LA Workspace)
 - Sentinel MS Connectors and Alerts (Dependent on SecurityInsights Solution)
 - Syslog VMSS (Dependent on "...-Ingestion" RG and LA Workspace)
 - CrowdStrike VM (Dependent on "...-Ingestion" RG and LA Workspace)
 - Qualys Integration (Dependent on "...-Ingestion" RG and LA Workspace)
