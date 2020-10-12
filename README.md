<center><img src="https://raw.githubusercontent.com/tobor88/CybereasonAPI/main/images/cyberreason.jpg" alt="Cybereason" width="25%" height="25%"></center>

# CybereasonAPI
 PowerShell module containing commands to easily interact with the Cybereason API. Once I get all the functions added I plan to add I will add this to PowerShell Gallery for easy installs.<br>
 __RESOURCE:__ [Cybereason API Documentation](https://nest.cybereason.com/documentation/api-documentation)

## Current Cmdlets
__Connect-CybereasonAPI__: This cmdlet is used to authenticate to the Cybereason API. This will create a global variable called $Session that will get used with the rest of the cmdletts in this module that need it.
```powershell
Connect-CybereasonAPI -Username 'admin@cybereason.com' -Passwd 'Password123!' -Server 'aaaaaaaa.cybereason.net' -Port '8443' -ClearHistory -Verbose
```

__Get-CybereasonReputations__: This cmdlet is used to view or download a CSV list of reputation informatino that have been manually configured on your environments Cybereason server.
[Documentation for Manage Reputations](https://nest.cybereason.com/documentation/api-documentation/all-versions/manage-reputations)
- Return a list of reputations that have been configured on Cybereason for your environment and view it in CSV format in your terminal window
- Return a list of reputations that have been configured on Cybereason for your environment and view it in CSV format and save it to a file
```powershell
Get-CybereasonReputations -Server aaaaaaaa.cybereason.net -Port '8443' -Verbose
# OR TO SAVE TO CSV FILE
Get-CybereasonReputations -Server aaaaaaaa.cybereason.net -Port '8443' -Path C:\Windows\Temp\CybereasonReputations.csv
```

__Set-CybereasonReputations__: This cmdlet is used to add or update a custom reputation on the Cybereason server instance. Using the Cybereason Reputation Management API, you can integrate and update threat intelligence from various sources to improve detections, view and update file reputations, and add items to the whitelist based on behavioral characteristics.
- Add or remove reputations for a file using its hash or filename by adding it to a whitelist or blacklist. You can also prevent execution of the file throughout your environment
- Add or remove reputations for an IP address by adding it to a whitelist or blacklist
- Add or remove reputations for a domain by adding it to a whitelist or blacklist
```powershell
Set-CybereasonReputations -Server 'aaaaaaaa.cybereason.net' -Port '8443' -Keys '1.1.1.1' -Modify whitelist -Action Add -PreventExecution false -Verbose
Set-CybereasonReputations -Server 'aaaaaaaa.cybereason.net' -Port '8443' -Keys '8.8.8.8','www.cybereason.com' -Modify whitelist -Action Remove -PreventExecution false -Verbose
Set-CybereasonReputations -Server 'aaaaaaaa.cybereason.net' -Port '8443' -File 'C:\Users\Enemy\badFile.exe','C:\Users\Enemy\persistence.exe' -Modify blacklist -Action Add -PreventExecution true -Verbose
```

__Get-CybereasonThreatIntel__: This cmdlet is used to communicate with every link under the "Get Threat Intel" section of the API documentation. 
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
 - Check for database updates <br>
[Documentation for Get Threat Intel](https://nest.cybereason.com/documentation/api-documentation/all-versions/get-threat-intel#get-threat-intel)
```powershell
Get-CybereasonThreatIntel -Domain 'www.cybereason.com','cybereason.com'
Get-CybereasonThreatIntel -IPAddress '1.1.1.1','1.0.0.1'
Get-CybereasonThreatIntel -MD5Hash FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
Get-CybereasonThreatIntel -DbUpdateCheck -ReputationAPI product_classification
```

## Still To Come Cmdlets
__Invoke-HuntAndInvestigate__: Using hunting queries and file search capabilities in the API, further your investigation of malicious behavior in your organization, including:
- Run investigative queries
- Search for files
- Get results of a previous file search
- Get results of a previous file search and export to CSV
- Return previous file searches
- Return previous file searches for all users
- Download a file
- Abort a file download operation
All of these capabilities help you improve security, uncover bad practices and deficiencies, and gain insight on tactical and strategic methods for threat prevention in your environment <br>
[Documentation for Hunt and Investigate](https://nest.cybereason.com/documentation/api-documentation/all-versions/hunt-and-investigate)

__Invoke-RespondToMalops__: By using the API you can retrieve Malops or isolate machines involved in a specific Malop. This can prove to be very useful in situations where you are remediating Malops in your ticketing system and you would like to synchronize that system with Cybereason Malop inbox.
- Get all Malops currently active
- Retrieve all Malops of all types
- Retrieve details on a specific Malop
- Perform all possible response actions on a Malop
- Perform all possible response actions on a Malop
- Isolate a machine connected with a Malop
- Remove a machine involved with a Malop from isolation
- Update a Malop’s status
- Add a comment to a Malop
- Get a list of Malop labels
- Create a Malop label
- Delete a Malop label
- Update Malop labels <br>
[Documentation for Respond to Malops](https://nest.cybereason.com/documentation/api-documentation/all-versions/respond-malops)

__Invoke-RespondToMalware__: By using the API you can retrieve details on malware. This enables you to address and investigate malware to prevent additional damage.
- Get a count of all Malware per type
- Query a specific type of Malware <br>
[Documentation for Respond to Malware](https://nest.cybereason.com/documentation/api-documentation/all-versions/respond-malware)

__Invoke-RemediateItems__: By using the API you can take remediation actions on Malops to limit or prevent additional damage.
- Remediate an item
- Check the status of a remediation
- Abort a remediation operation
- Get remediation statuses for a particular Malop <br>
[Documentation for Remediate Items](https://nest.cybereason.com/documentation/api-documentation/all-versions/remediate-items-0)

__Add-CustomDetectionRule__: Custom detection rules created via API should be created only after adequate research regarding precision and coverage has been completed. Creating a custom detection rule that is not specific enough can have detrimental impact on retention and overall performance of the environment.
- Retrieve a list of all active custom detection rules
- Retrieve a list of all disabled custom detection rules
- Retrieve a list of all available root causes
- Retrieve a list of all available Malop detection types
- Retrieve a list of all available Malop activity types
- Create a custom rule
- Update a custom rule
- Get the modification history <br>
[Documentation for Add Custom Detection Rules](https://nest.cybereason.com/documentation/api-documentation/all-versions/add-custom-detection-rules)

__Set-MachineIsolationRules__: Normally, when a machine is isolated, there is absolutely no communication allowed with the machine. This can sometimes limit the ability of an analyst or administrator to perform investigation or triage on that machine. However, you can add isolation exception rules to help you allow limited communication to an isolated machine
- Retrieve a list of isolation rules 
- Create an isolation rule
- Update an isolation rule
- Delete an isolation rule <br>
[Documentation for Machine Isolation Rules](https://nest.cybereason.com/documentation/api-documentation/all-versions/set-machine-isolation-rules)

__Manage Sensors (Multiple Cmdlets)__: Cybereason enables you to manage your Sensors from the API, including configuring NGAV settings for the sensors, starting and stopping collection on the Sensors, restarting Sensors, deleting or removing Sensors, archiving Sensors, and upgrading Sensors. _(Get-Sensor, Set-Sensor, Remove-Sensor, Restart-Sensor, Create-Sensor, Add-Sensor, Update-Sensor, Save-Sensor)_
- Get a list of all Sensors
- Retrieve a list of all actions on Sensors
- Set the Anti-Ransomware mode for a Sensor
- Set the Application Control mode for a Sensor
- Set the Anti-Malware status for a Sensor
- Set the Powershell protection mode for a Sensor
- Start collection on a Sensor
- Stop collection on a Sensor
- Delete a Sensor
- Restart a Sensor
- Retrieve logs from a Sensor
- Download logs from a Sensor
- Download a CSV list of Sensors
- Upgrade the Sensor
- Abort in-progress operations
- Archive a Sensor
- Remove a Sensor from archive
- Add/update or remove Sensor tags
- Retrieve Sensor tags for a Sensor
- Retrieve a list of sensor group
- Create a sensor group
- Edit a sensor group
- Add a sensor to a sensor group
- Remove a sensor from a group <br>
[Documentation for Manage Sensors](https://nest.cybereason.com/documentation/api-documentation/all-versions/manage-sensors)

Below are images of the results from different Get-CybereasonThreatIntel commands.
![Get-CybereasonThreatIntel Result Image](https://raw.githubusercontent.com/tobor88/CybereasonAPI/main/images/GetThreatInfoImage.png)
