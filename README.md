# CybereasonAPI
 PowerShell module containing commands to easily interact with the Cybereason API. Once I get all the functions added I plan to add I will add this to PowerShell Gallery for easy installs.<br>
 __RESOURCE:__ [Cybereason API Documentation](https://nest.cybereason.com/documentation/api-documentation)

### Current Cmdlets
__Get-ThreatIntel__: This cmdlet is used to communicate with every link under the "Get Threat Intel" section of the API documentation. 
It can perform the following actions.
 - Get a file reputation	
 - Get reputation for a domain	
 - Get reputation for an IP address	
 - Retrieve product classification information	
 - Retrieve process classification information	
 - Retrieve process hierarchy information
 - Retrieve file extension information	
 - Retrieve port information
 - Retrieve collection information
 - Retrieve a list of IP address reputations
 - Retrieve a list of domain reputations
 - Check for database updates
If you have a Cybereason Nest Account you can view more information [HERE](https://nest.cybereason.com/documentation/api-documentation/all-versions/get-threat-intel#get-threat-intel)
Below are images of the results from different Get-ThreatIntel commands.
![Get-ThreatIntel Result Image](https://raw.githubusercontent.com/tobor88/CybereasonAPI/main/images/GetThreatInfoImage.png)
