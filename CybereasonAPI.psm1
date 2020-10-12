<#
.SYNOPSIS
This cmdlet is used to authenticate to the Cybereason API. Once this is done a global $Session variable is created that will be used for all other cmdlets in this module.


.DESCRIPTION
This cmdlet creates a $Session variable that will be used with all the other cmdlets in this module to authenticate requests made to the Cybereason API.


.PARAMETER Server
This parameter defines the server IP address or domain name your Cybereason server is running on

.PARAMETER Port
This parameter is used to define the port your Cybereason server is on. This is usually 443 or 8443. The default value is 443.

.PARAMETER Username
This is the email address you use to sign into Cybereason

.PARAMETER Passwd
This is the password you use to sign into your Cybereason account. The session history gets cleared to attempt preventing the password from appearing in the session logs. This does not clear the events logs. I suggest only letting administrators view the PowerShell event logs.


.EXAMPLE
Connect-CybereasonAPI -Server 123.45.67.78 -Port 8443 -Username admin@cyberason.com -Passwd "Password123!"
# This example authenticates to the Cybereason API and creates a $Session variable to be used by other cmdlets. This also clears the current PowerShell Session History.


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None


.LINK
https://nest.cybereason.com/documentation/api-documentation
https://roberthsoborne.com
https://osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
Function Connect-CybereasonAPI {
    [CmdletBinding()]
        param(
            [Parameter(
                Position=0,
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Enter the email you wish to sign in with `n[E] EXAMPLE: admin.user@domain.com")]  # End Parameter
            [ValidateNotNullOrEmpty()]
            [String]$Username,

            [Parameter(
                Position=1,
                Mandatory=$True,
                ValueFromPipeline=$False)]  # End Parameter
            [ValidateNotNullOrEmpty()]
            [String]$Passwd,

            [Parameter(
                Position=2,
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Enter the IP address or hostname of your Cybereason server as well as the port. Spearate values with a : `n[E] EXAMPLE: 10.0.0.1:443 `n[E] EXAMPLE: asdf.cybereason.com:8443")]
            [ValidateNotNullOrEmpty()]
            [String]$Server,

            [Parameter(
                Position=3,
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [ValidateRange(1,65535)]
            [String]$Port = "443",

            [Parameter(
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$ClearHistory
        )  # End param

    Write-Verbose "Validating username parameter is in email address format"
    Try 
    {
    
        $Null = [MailAddress]$Username
    
    }  # End Try
    Catch 
    {

        Throw "[x] The username you defined is not a valid email address."
        
    }  # End Catch


    $Uri = "https://" + $Server + ":" + $Port + "/login.html"

    Write-Verbose "Ensuring TLS 1.2 is being used"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $Body = @{
        username="$Username"
        password="$Passwd"
    }  # End Body

    Write-Verbose "Sending request to $Uri"
    $Results = Invoke-WebRequest -Method POST -Uri $Uri -ContentType "application/x-www-form-urlencoded" -Body $Body -SessionVariable 'Session'
    
    If ($Results.StatusCode -eq '200')
    {

        Write-Output "[*] Successfully created an authenticated session to the Cybereason API."

    }  # End If

    $Global:Session = $Session
    $Global:Server = $Server
    $Global:Port = $Port

    If ($ClearHistory.IsPresent)
    {

        Clear-History -Verbose
        Write-Warning "This PowerShells session history has just been cleared to prevent the clear text password from appearing in log files. This does not clear the PowerShell Event log. Only allow administrators to view that log."
    
    }  # End If
    Else 
    {

        Write-Warning "The -ClearHistory parameter was not specified. If you wish to remove the clear text password from this session command history you will need to manually issue the command Clear-History"

    }  # End Else

}  # End Function Connect-CybereasonAPI


<#
.SYNOPSIS
This cmdlet was created to quickly and easily perform all Threat Intelligence tasks that the Cybereason API allows such as looking up a domain or IP address.


.DESCRIPTION
Easily and quickly communicate with the Cyberason API to discover threat intel on an IP address, domain, product, process, file extension or check for database updates avaialable in those categories.


.PARAMETER Md5Hash
This parameter accepts an MD5 hash of a file to check the reputation of the files signature against the Cybereason database. The -FileToHash parameter can be used if you do not already have the hash value available

.PARAMETER FileToHash
This parameter defines a file that you want to check against the cybereason reputation database. If you do not have the hash of the file this will automtically get the hash for you and check it's reputation

.PARAMETER Domain
This parameter defines a domain to check against the malicious domain database and discover info such as when the domain was first registered

.PARAMETER IPAddress
This parameter defines the IP address to be checked against the Cyberason malicious IP address database

.PARAMETER ProductClassification
This switch parameter indicates you wish to retrieve product classification information

.PARAMETER ProcessClassification
This switch parameter indicates you wish to retrieve process classification information

.PARAMETER ProcessHierarchy
This switch parameter indicates you wish to retrieve process hierarchy information

.PARAMETER FileExtension
This switch parameter indicates you wish to retrieve file extension information  

.PARAMETER PortInfo
This switch parameter indicates you wish to retrieve port information

.PARAMETER CollectionInfo
This switch parameter indicates you wish to retrieve collection information 

.PARAMETER IPReputation
This switch parameter indicates you wish to retrieve a list of IP address reputations 

.PARAMETER DomainRep
This switch parameter indicates you wish to retrieve a list of domain reputations

.PARAMETER DbUpdateCheck
This switch parameter indicates you wish to check for database updates 


.EXAMPLE
Get-CybereasonThreatIntel -Md5Hash 'D7AB69FAD18D4A643D84A271DFC0DBDF'
# This example returns details on a file’s reputation based on the Cybereason threat intelligence service using the MD5 hash. If you do not already have the hash, use the -FileToHash parameter to have it obtained automtacilly for you.

.EXAMPLE
Get-CybereasonThreatIntel -Md5Hash 'D7AB69FAD18D4A643D84A271DFC0DBDF','5D997A651DA137B68B15EAC157A4FC42'
# This example returns details on two file reputations based on the Cybereason threat intelligence service using the MD5 hash. If you do not already have the hash, use the -FileToHash parameter to have it obtained automtacilly for you.

.EXAMPLE
Get-CybereasonThreatIntel -Md5Hash (Get-FileHash -Algorithm MD5 -Path C:\Users\Public\Desktop\AlwaysInstallElevatedCheck.htm).Hash
# This example gets the file hash of a file on the OS and determines if it is malicious or not

.EXAMPLE
Get-CybereasonThreatIntel -FileToHash C:\Windows\System32\cmd.exe
# This example returns details on the file C:\Windows\System32\cmd.exe's reputation based on the Cybereason threat intelligence service. This determines the MD5 hash automatically of the file you define. If you already have the hash enter it using the -Md5Hash parameter instead of this one.

.EXAMPLE
Get-CybereasonThreatIntel -FileToHash 'C:\Windows\System32\cmd.exe','C:\Windows\Sysmon.exe'
# This example returns details on the file C:\Windows\System32\cmd.exe and C:\WIndows\Sysmon.exe's reputation based on the Cybereason threat intelligence service. This determines the MD5 hash automatically of the file you define. If you already have the hash enter it using the -Md5Hash parameter instead of this one.

.EXAMPLE
Get-CybereasonThreatIntel -Domain www.cybereason.com
# This example returns details on domain reputations for www.cybereason.com based on the Cybereason threat intelligence service.

.EXAMPLE
Get-CybereasonThreatIntel -Domain 'www.cybereason.com',cybereason.net'
# This example returns details on domain reputations for www.cybereason.com and cybereason.net based on the Cybereason threat intelligence service.

.EXAMPLE
Get-CybereasonThreatIntel -IPAddress 1.1.1.1
# This example returns details on IP address reputations for 1.1.1.1 based on the Cybereason threat intelligence service. 

.EXAMPLE
Get-CybereasonThreatIntel -IPAddress '1.1.1.1','208.67.222.222'
# This example returns details on IP address reputations for 1.1.1.1 and 208.67.222.222 based on the Cybereason threat intelligence service. 

.EXAMPLE
Get-CybereasonThreatIntel -ProductClassification
# This example retrieves product classification information

.EXAMPLE
Get-CybereasonThreatIntel -ProcessClassification
# This example retrieves process classification information

.EXAMPLE
Get-CybereasonThreatIntel -ProcessHierarchy
# This example retrieves process hierarchy information

.EXAMPLE
Get-CybereasonThreatIntel -FileExtension
# This example retrieves file extension information

.EXAMPLE
Get-CybereasonThreatIntel -PortInfo
# This example returns information on all ports

.EXAMPLE
Get-CybereasonThreatIntel -CollectionInfo
# This example returns information on collection information used by the Cybereason platform

.EXAMPLE
Get-CybereasonThreatIntel -IPReputation
# This example returns a list of IP Address reputations

.EXAMPLE
Get-CybereasonThreatIntel -DomainReputation
# This example returns a list of Domain reputations

.EXAMPLE
Get-CybereasonThreatIntel -DbUpdateCheck -ReputationAPI const
# The -DbUpdateCheck switch parameter checks fro Cybereason sensor updates that are available for collection information

.EXAMPLE
Get-CybereasonThreatIntel -DbUpdateCheck -ReputationAPI domain_reputation
# The -DbUpdateCheck switch parameter checks fro Cybereason sensor updates that are available for domain reputations

.EXAMPLE
Get-CybereasonThreatIntel -DbUpdateCheck -ReputationAPI file_extension
# The -DbUpdateCheck switch parameter checks fro Cybereason sensor updates that are available for file extensions

.EXAMPLE
Get-CybereasonThreatIntel -DbUpdateCheck -ReputationAPI ip_reputation
# The -DbUpdateCheck switch parameter checks fro Cybereason sensor updates that are available for IP Address reputations

.EXAMPLE
Get-CybereasonThreatIntel -DbUpdateCheck -ReputationAPI process_classification
# The -DbUpdateCheck switch parameter checks fro Cybereason sensor updates that are available for process classifications

.EXAMPLE
Get-CybereasonThreatIntel -DbUpdateCheck -ReputationAPI process_hierarchy
# The -DbUpdateCheck switch parameter checks fro Cybereason sensor updates that are available for process hierarchy information

.EXAMPLE
Get-CybereasonThreatIntel -DbUpdateCheck -ReputationAPI product_classification
# The -DbUpdateCheck switch parameter checks fro Cybereason sensor updates that are available for product classification information


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None


.LINK
https://nest.cybereason.com/documentation/api-documentation
https://roberthsoborne.com
https://osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
Function Get-CybereasonThreatIntel {
    [CmdletBinding()]
        param(
            [Parameter(
                ParameterSetName='Md5Hash',
                Mandatory=$True,
                ValueFromPipeline=$False)]  # End Parameter
            [Alias('Hash','MD5')]
            [ValidateScript({$_.Length -eq 32})]
            [String[]]$Md5Hash,

            [Parameter(
                ParameterSetName='FileToHash',
                Mandatory=$True,
                ValueFromPipeline=$False)]  # End Parameter
            [Alias('Path','FilePath','f')]
            [ValidateScript({Test-Path -Path $_})]
            [String[]]$FileToHash,

            [Parameter(
                ParameterSetName='Domain',
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Define a domain to look up threat information on`n[E] EXAMPLE: www.cybereason.com")]  # End Parameter
            [Alias('d')]
            [ValidateScript({$_ -Like "*.*"})]
            [String[]]$Domain,

            [Parameter(
                ParameterSetName='IPAddress',
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Define an IP Address to look up threat information on`n[E] EXAMPLE: 1.1.1.1")]  # End Parameter
            [Alias('ip')]
            [String[]]$IPAddress,

            [Parameter(
                ParameterSetName='ProductClassification')]  # End Parameter
            [Switch][Bool]$ProductClassification,

            [Parameter(
                ParameterSetName='ProcessClassification')]  # End Parameter
            [Switch][Bool]$ProcessClassification,

            [Parameter(
                ParameterSetName='ProcessHierarchy')]  # End Parameter
            [Switch][Bool]$ProcessHierarchy,

            [Parameter(
                ParameterSetName='FileExtension')]  # End Parameter
            [Switch][Bool]$FileExtension,

            [Parameter(
                ParameterSetName='PortInfo')]  # End Parameter
            [Switch][Bool]$PortInfo,

            [Parameter(
                ParameterSetName='CollectionInfo')]  # End Parameter
            [Switch][Bool]$CollectionInfo,
           
            [Parameter(
                ParameterSetName='IPReputation')]  # End Parameter
            [Switch][Bool]$IPReputation,

            [Parameter(
                ParameterSetName='DomainReputation')]  # End Parameter
            [Switch][Bool]$DomainReputation,

            [Parameter(
                ParameterSetName='DbUpdateCheck')]  # End Parameter
            [Switch][Bool]$DbUpdateCheck,

            [Parameter(
                ParameterSetName='DbUpdateCheck',
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Enter the reputaion API value to be added to the query of the API's URI. This goes here in the URI, /download_v1/<HERE>/service `n[E] EXMAPLE: process_classification")]  # End Parameter
            [ValidateSet("ip_reputation","domain_reputation","process_classification","file_extension","process_hierarchy","process_hierarchy","product_classification","const")]
            [String]$ReputationAPI
            
        )  # End param

    $Obj = @()
    $Site = 'https://sage.cybereason.com/rest/'

    Switch ($PSBoundParameters.Keys)
    {

        'Md5Hash' {

            $Uri = $Site + 'classification_v1/file_batch'

            ForEach ($MD in $Md5Hash)
            {

                $JsonData = '{"requestData": [{"requestKey": {"md5": "' + $MD + '"} }] }'

                Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
                $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

                $Results = $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty "classificationResponses"
                $MD5 = ($Results.requestKey.md5 | Out-String).Trim()
                $SHA1 = ($Results.requestKey.sha1 | Out-String).Trim()
                $MaliciousScore = $Results.aggregatedResult.maliciousClassification
                $ProductType = ($Results.aggregatedResult.productClassification.productType | Out-String).Trim()
                $Type = ($Results.aggregatedResult.productClassification.Type | Out-String).Trim()
                
                $Obj += New-Object -TypeName PSObject -Property @{md5="$MD5"; sha1="$SHA1"; MaliciousScore="$MaliciousScore"; ProductType="$ProductType"; Type="$Type"}

            }  # End ForEach
                
            $Obj

        }  # End Switch FileRep

        'FileToHash' {

            $Uri = $Site + 'classification_v1/file_batch'

            ForEach ($FilesMD5 in $FileToHash)
            {
                
                $FileHash = (Get-FileHash -Algorithm MD5 -Path $FilesMD5).Hash
                $JsonData = '{"requestData": [{"requestKey": {"md5": "' + $FileHash + '"} }] }'

                Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
                $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

                $Results = $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty "classificationResponses"
                $MD5 = ($Results.requestKey.md5 | Out-String).Trim()
                $SHA1 = ($Results.requestKey.sha1 | Out-String).Trim()
                If ($SHA1.Length -ne 40) { $SHA1 = (Get-FileHash -Algorithm SHA1 -Path $FilesMD5).Hash}
                $MaliciousScore = $Results.aggregatedResult.maliciousClassification
                $ProductType = ($Results.aggregatedResult.productClassification.productType | Out-String).Trim()
                $Type = ($Results.aggregatedResult.productClassification.Type | Out-String).Trim()

                $Obj += New-Object -TypeName PSObject -Property @{md5="$MD5"; sha1="$SHA1"; MaliciousScore="$MaliciousScore"; ProductType="$ProductType"; Type="$Type"}

                Clear-Variable -Name FileHash,JsonData,Results,MD5,SHA1,MaliciousScore,ProductType,Type

            }  # End ForEach

            $Obj

        }  # End Switch FileRep

        'IPAddress' {

            $Uri = $Site + 'classification_v1/ip_batch'
            $IPv4Regex = '(((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))'

            ForEach ($IPAddr in $IPAddress)
            {

                Write-Verbose "Chekcing $IPAddr"
                If ($IPAddr -Match $IPv4Regex)
                {

                    $IPType = 'Ipv4'

                }  # End If
                Else 
                {

                    $IPType = 'Ipv6'

                }  # End Else

                $JsonData = '{"requestData": [{"requestKey": {"ipAddress": "' + $IPAddr + '","addressType": "' + $IPType + '"} }] }' 

                Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
                $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

                $Results = $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty "classificationResponses"
                $IPA = ($Results.requestKey.ipAddress | Out-String).Trim()
                $AddressType = ($Results.requestKey.addressType | Out-String).Trim()
                $MaliciousScore = $Results.aggregatedResult.maliciousClassification
                $FirstSeen = Get-Date ($Results.aggregatedResult.firstSeen)
                $AllowFurther = ($Results.allowFurtherClassification | Out-String).Trim()
                $CPID = ($Results.cpId | Out-String).Trim()

                $Obj += New-Object -TypeName PSObject -Property @{IP=$IPA; Type=$AddressType; MaliciousScore=$MaliciousScore; FirstSeen=$FirstSeen; AllowFurtherClassification=$AllowFurther; CPID=$CPID} 

            }  # End ForEach

            $Obj

        }  # End Switch IPBat

        'Domain' {

            $Uri = $Site + 'classification_v1/domain_batch'

            ForEach ($Dom in $Domain)
            {
                
                Write-Verbose "Testing $Dom"

                $JsonData = '{"requestData": [{"requestKey": {"domain": "' + $Dom + '"} }] }'

                Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
                $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

                $Results = $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty "classificationResponses"

                $Doma = ($Results.requestKey.domain | Out-String).Trim()
                $Source = ($Results.aggregatedResult.maliciousClassification.source | Out-String).Trim()
                $MaliciousScore = $Results.aggregatedResult.maliciousClassification
                $FirstSeen = Get-Date -Date ($Results.aggregatedResult.firstSeen)
                $AllowFurther = ($Results.allowFurtherClassification | Out-String).Trim()
                $CPID = ($Results.cpId | Out-String).Trim()
                $CPType = ($Results.cpType | Out-String).Trim()

                $Obj += New-Object -TypeName PSObject -Property @{Domain=$Doma; Source=$Source; MaliciousScore=$MaliciousScore; FirstSeen=$FirstSeen; AllowFurtherClassification=$AllowFurther; CPID=$CPID; CPType=$CPType}
 
            }  # End ForEach

            $Obj

        }  # End Switch DomainBatch
        
        'ProductClassification' {

            $Uri = $Site + 'download_v1/productClassifications'
            $JsonData = "{}"

            Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

            $Results = $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty "recordList" | `
            ForEach-Object {
                $Name = ($_.Key.name | Out-String).Trim()
                $Signer = ($_.Value.signer | Out-String).Trim()
                $Type = ($_.Value.type | Out-String).Trim()
                $Title = ($_.Value.title | Out-String).Trim()

                $Obj += New-Object -TypeName PSObject -Property @{Name="$Name"; Signer=$Signer; Type=$Type; Title="$Title"}

            }  # End For

            $Obj

        }  # End Switch ProductClassification

        'ProcessClassification' {

            $Uri = $Site + 'download_v1/process_classification'
            $JsonData = "{}"

            Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

            $Results = $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty "recordList" | `
            ForEach-Object {
                $ProcessName = ($_.Key.name | Out-String).Trim()
                $Title = ($_.Value.title | Out-String).Trim()
                $ProductName = ($_.Value.productName | Out-String).Trim()
                $CompanyName = ($_.Value.companyName | Out-String).Trim()
                $fileDescription = ($_.Value.fileDescription | Out-String).Trim()
                $filePath = ($_.Value.path | Out-String).Trim()


                $Obj += New-Object -TypeName PSObject -Property @{ProcessName="$ProcessName"; Title="$Title"; ProductName=$ProductName; CompanyName=$CompanyName; FileDescription=$fileDescription; FilePath=$FilePath}

            }  # End For

            $Obj

        }  # End Switch ProcessClassification

        'ProcessHierarchy' {

            $Uri = $Site + 'download_v1/process_hierarchy'
            $JsonData = "{}"

            Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

            $Results = $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty "recordList" | `
            ForEach-Object {

                $Parent = ($_.Value.parent | Out-String).Trim()
                $ProcessName = ($_.Key.name | Out-String).Trim()

                $Obj += New-Object -TypeName PSObject -Property @{Parent="$Parent"; ProcessName="$ProcessName"}

            }  # End For
            
            $Obj

        }  # End Switch ProcessHierarchy

        'FileExtension' {

            $Uri = $Site + 'download_v1/file_extension'
            $JsonData = "{}"

            Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

            $Obj = $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty "recordList" | Select-Object -ExpandProperty "Value" | Select-Object -Property Description,Type
            
            $Obj

        }  # End Switch FileExtension

        'PortInfo' {

            $Uri = $Site + 'download_v1/port'
            $JsonData = "{}"

            Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

            $Results = $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty "recordList" | `
            ForEach-Object {

                $Port = ($_.Key.port | Out-String).Trim()
                $Protocol = ($_.Key.protocol | Out-String).Trim()
                $Type = ($_.Value.type | Out-String).Trim()
                $ShortDescription = ($_.Value.shortDescription | Out-String).Trim()
                $Source = ($_.Value.sources | Out-String).Trim()
                $LongDescr = ($_.Value.longDescription | Out-String).Trim()

                $Obj += New-Object -TypeName PSObject -Property @{Port="$Port"; Protocol="$Protocol"; Type=$Type; ShortDescription=$ShortDescription; Source=$Source; LongDescription=$LongDescr}

            }  # End ForEach-Object

            $Obj

        }  # End Switch PortInfo

        'CollectionInfo' {

            $Uri = $Site + 'download_v1/const'
            $JsonData = "{}"

            Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

            $Results = $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty "recordList" | `
            ForEach-Object {
                $Name = ($_.Key.name | Out-String).Trim()
                $Data = ($_.Value.data | Out-String).Trim()

                $Obj += New-Object -TypeName PSObject -Property @{Name="$Name"; Data="$Data"}

            }  # End For 
            
            $Obj

        }  # End Switch CollectionInfo

        'IPReputation' {

            $Uri = $Site + 'download_v1/ip_reputation'
            $JsonData = "{}"

            Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

            $Results = $Response.Content | ConvertFrom-Json
            For ($i = 0; $i -le $Results.ipReputationResponseList.Count; $i++)
            {

                $IPAddress = ($Results.ipReputationResponseList.requestkey.ipaddress[$i] | Out-String).Trim()
                $AddressType = ($Results.ipReputationResponseList.requestkey.addressType[$i] | Out-String).Trim()
                $ReputationSource = ($Results.ipReputationResponseList.aggregatedResult.reputationSource[$i] | Out-String).Trim()
                $ReputationScore = ($Results.ipReputationResponseList.aggregatedResult.reputationScore[$i] | Out-String).Trim()

                $Obj += New-Object -TypeName PSObject -Property @{IPAddress="$IPAddress"; AddressType="$AddressType"; ReputationSource="$ReputationSource"; ReputationScore="$ReputationScore"}

            }  # End For 
            
            $Obj

        }  # End IPReputation Switch

        'DomainReputation' {

            $Uri = $Site + 'download_v1/domain_reputation'
            $JsonData = "{}"

            Write-Verbose "Sending Threat Intel JSON data to Cybereason's API"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

            $Results = $Response.Content | ConvertFrom-Json
            For ($i = 0; $i -le ($Results.domainReputationResponseList).Count; $i++)
            {

                $Domain = ($Results.domainReputationResponseList.requestkey[$i] | Out-String).Trim()
                $ReputationSource = ($Results.domainReputationResponseList.aggregatedResult.reputationSource[$i] | Out-String).Trim()
                $ReputationScore = ($Results.domainReputationResponseList.aggregatedResult.reputationScore[$i] | Out-String).Trim()

                $Obj += New-Object -TypeName PSObject -Property @{Domain="$Domain"; ReputationSource="$ReputationSource"; ReputationScore="$ReputationScore"}

            }  # End For
            
            $Obj 
        
        }  #End Switch DomainReputation

        'DbUpdateCheck' {

            $Uri = $Site + 'download_v1/' + $ReputationAPI + '/service'
            $JsonData = "{}"

            Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

            $Obj = $Response.Content | ConvertFrom-Json
            
            $Obj

        }  # End Switch DbUpdateCheck

    }  # End Switch

}  # End Function Get-CybereasonThreatIntel


<#
.SYNOPSIS
Returns a CSV list of custom reputations for files, IP addresses, and domain names. These reputations are specific to your organization.


.DESCRIPTION
This cmdlet is used to download a CSV list of custom reputations for files, IP addresses, and domains that were manually set up in your environment.


.PARAMETER Path
This parameter defines the path and filename to save the CSV results.


.EXAMPLE
Get-CybereasonReputations -Path C:\Windows\Temp\CybereasonRepuations.csv
# This example gets the current repuations of files, IP addresses, and domains configured in your environment and returns CSV related results.


.INPUTS
None


.OUTPUTS
System.String 
The CSV list is sent to the file designated in the Path parameter.


.LINK
https://nest.cybereason.com/documentation/api-documentation/all-versions/get-reputation#getreputations
https://roberthsoborne.com
https://osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
Function Get-CybereasonReputations {
    [CmdletBinding()]
        param(
            [Parameter(
                Position=1,
                Mandatory=$False)]  # End Parameter
            [String]$Path
        )  # End param

    $Uri = 'https://' + $Server + ":$Port" + '/rest/classification/download'

    Write-Verbose "Sending request to $Uri"
    If (($Path) -and ($Response.StatusCode -eq '200'))
    {

        Write-Verbose "Downloading file to $Path"
        Invoke-RestMethod -URI $Uri -WebSession $Session -ContentType "application/json" -Method GET -OutFile "$Path"

    }  # End If
    Else
    {
        
        Write-Verbose "Returning CSV formatted results to window"
        Invoke-RestMethod -URI $Uri -WebSession $Session -ContentType "application/json" -Method GET

    }  # End Else
    
}  # End Function Get-CybereasonReputations


<#
.SYNOPSIS
This cmdlet is used to update the custom set reputations of files, IP addresses, or domain names in an environment with Cybereason.


.DESCRIPTION
This cmdlet can add or remove IP addresses, domains, and file hashes to a blacklisit or whitelist to change the reputation of that item in the eyes of Cybereason.


.PARAMETER Keys
The file hash value (either MD5 or SHA1), IP address, or domain name for which to set a custom reputation.

.PARAMETER File
If you do not know the hash of a file or files you wish to modify the reputations of, you can simply enter the path to the file here and this will obtain the hash automatically for you. This can be used to replace the -Keys parameter.

.PARAMETER Modify
Modify the reputation of an item by adding a rule to the blacklist or whitelist

.PARAMETER Action
Instructs Cybereason to add or remove a reputation. Set the value to Add or Remove to modify the defined reputations.

.PARAMETER PreventExecution
This parameter indicates whether to prevent the file’s execution with Application Control. Note this option is applicable for the File type. If your request includes IP addresses or domain names to update, you must set this parameter to false.


.EXAMPLE
Set-CybereasonReputations -Keys '1.1.1.1' -Modify Whitelist -Action Add -PreventExecution False
# This example sets the Cybereason repuations of IP address 1.1.1.1 by adding it to the whitelist. Because this is an IP address the -PreventExecution parameter needs to be false. This will be modified automatically in the script if set incorrectly.

.EXAMPLE
Set-CybereasonReputations -Keys 'maliciousdomain.com' -Modify Blacklist -Action Add -PreventExecution False
# This example sets the Cybereason repuations of domain maliciousdomain.com by adding it to the blacklist. Because this is not a file hash the -PreventExecution parameter needs to be false. This will be modified automatically in the script if set incorrectly.

.EXAMPLE
Set-CybereasonReputations -Keys 'badguy.com','badperson.com' -Modify Blacklist -Action Add -PreventExecution False
# This example sets the Cybereason repuations of domain badguy.com and badperson.com by adding them to the blacklist. Because this is not a file hash the -PreventExecution parameter needs to be false. This will be modified automatically in the script if set incorrectly.

.EXAMPLE
Set-CybereasonReputations -Keys 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' -Modify 'Blacklist' -Action 'Add' -PreventExecution 'True'
# This example sets the Cybereason repuations of a file with the defined SHA1 hash value and adds it to the blacklist. Prevent Execution is set to true which will prevent all devices in an environment from executing this file when App Control is enabled in Cybereason.

.INPUTS
None


.OUTPUTS
None


.LINK
https://nest.cybereason.com/documentation/api-documentation/all-versions/get-reputation#getreputations
https://roberthsoborne.com
https://osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
Function Set-CybereasonReputations {
    [CmdletBinding()]
        param(
            [Parameter(
                ParameterSetName='Keys',
                Mandatory=$True,
                ValueFromPipeline=$False)]  # End Parameter
            [String[]]$Keys,

            [Parameter(
                ParameterSetName='File',
                Mandatory=$True,
                ValueFromPipeline=$False)]
            [Alias('f','Path','FilePath')]
            [ValidateScript({Test-Path -Path $_})]
            [String[]]$File,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False)]  # End Parameter
            [ValidateSet('blacklist','whitelist')]
            [String]$Modify,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False)]
            [ValidateSet('Add','Remove')]
            [String]$Action,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Alias('Prevent')]
            [ValidateSet('true','false')]
            [String]$PreventExecution = 'false'
        )  # End param


    $Uri = "https://" + $Server + ":" + $Port + '/rest/classification/update '
    Switch ($Action)
    {

        'Add' { $Remove = 'false' }
        'Remove' { $Remove = 'true' }

    }  # End Switch


    If ($PSBoundParameters.Keys -eq 'File')
    {

        ForEach ($F in $File)
        {

            $Hash = (Get-FileHash -Algorithm MD5 -Path $F).Hash
            If ($PreventExecution -like 'true')
            {

                Write-Warning "You are about to prevent the execution of this file on all devices in your environment"
                $Answer = Read-Host -Prompt "Are you sure you wish to perform this action? [Y/n]"

                If ($Answer -like 'n')
                {

                    $PreventExecution = 'false'

                }  # End If
                Else 
                {

                    Write-Output "[*] Preventing the execution of the file with hash : $F"

                }  # End Else

            }  # End If

            $JsonData = '[{"keys": ["' + $Hash + '"],"maliciousType": "' + $Modify + '", "prevent": "' + $PreventExecution + '", "remove": "' + $Remove + '"}]'
            
            Write-Verbose "Sending request to $Uri"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData -WebSession $Session
            $Response.Content | ConvertFrom-Json

        }  # End ForEach

    }  # End Switch File
    Else 
    {

        $IPv4Regex = '(((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))'
        ForEach ($Key in $Keys)
        {
                
            Write-Verbose "Ensuring the Prevent Execution value is set to false when the Key value defined is an IP address or domain name"
            If ((!($Key.Length -eq 32)) -or (!($Key.Length -eq 40)) -or ($Key -Match $IPv4Regex) -or ($Key -like "*.*"))
            {

                $PreventExecution = 'false'

            }  # End If

            $JsonData = '[{"keys": ["' + $Key + '"],"maliciousType": "' + $Modify + '", "prevent": "' + $PreventExecution + '", "remove": "' + $Remove + '"}]'
        
            Write-Verbose "Sending request to $Uri"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData -WebSession $Session
            $Response.Content | ConvertFrom-Json

        }  # End ForEach

    }  # End Else
    
}  # End Function Set-CybereasonReputations