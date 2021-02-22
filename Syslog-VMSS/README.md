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
<a href="https://portal.azure.com/#create/Microsoft.Template/uri/https://raw.githubusercontent.com/PUNCH-Cyber/Azure-Public/main/Syslog-VMSS/Syslog-VMSS-ub-Template.json" target="_blank">
    <img src="https://aka.ms/deploytoazurebutton"/>
</a>
