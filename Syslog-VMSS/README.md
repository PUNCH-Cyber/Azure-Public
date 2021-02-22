# Scaleable SYSLOG & CEF Collection using VMSS

Sample is an ARM template that will deploy a Linux (RedHat or Unbuntu) Virtual Machine Scale Set.

The ARM template will deploy everything needed:
* Virtual Machine Scale
* Autoscale settings
* Storage Account
* Network Security Group
* Virtual Network
* Subnet
* Public IP Address
* Load Balancer

The ARM template includes the cloud init files which runs commands on the VM instance when it is deployed.

## Deploy Unbuntu VMSS
<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw%2Egithubusercontent%2Ecom%2FPUNCH%2DCyber%2FAzure%2DPublic%2Fmain%2FSyslog%2DVMSS%2FSyslog%2DVMSS%2Dub%2DTemplate%2Ejson" target="_blank">
    <img src="https://aka.ms/deploytoazurebutton"/>
</a>
