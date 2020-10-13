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
    $Global:JSession = $Session.Cookies.GetCookies($uri).Value
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


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


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
    If ($Path.Length -gt 0)
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


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


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


<#
.SYNOPSIS
This cmdlet is used to perform remediation actions on a specific process, file, or registry key


.DESCRIPTION
This uses the Cybereason API to perform a remediation action on a specific file, process, or registry key.


.PARAMETER MalopID
The unique ID assigned by the Cybereason platform for the Malop. This ID is found when you retrieve the list of Malops. For details on getting this ID, see, Get Malops. You can perform remediation without this malop ID.

.PARAMETER InitiatorUserName
The Cybereason user name for the user performing the remediation.

.PARAMETER MachineId
The unique GUID for the machine. Note this is different from the sensor ID (pylumID) value.

.PARAMETER TargetID
The unique GUID for the process or file to remediate. You can find this GUID in the response when you perform an investigation query for a process. If you provide a Malop ID in the request, do not add this field in the request. Note that using the targetId parameter is supported only for processes (the KILL_PROCESS action) and files (the QUARANTINE_FILE or UNQUARANTINE_FILE action). If you use the UNQUARANTINE_FILE action, the targetId (GUID) value is different than the GUID of the original file for the QUARANTINE_FILE action. You can find this GUID for the quarantined file by running a query with the Quarantine File Element.

.PARAMETER ActionType
The remediation action to perform. Possible values include:
KILL_PROCESS. Use this option to immediately stop the process associated with the root cause of the Malop.
DELETE_REGISTRY_KEY. Use this option to remove any registry keys detected as malicious as part of the Malop.
QUARANTINE_FILE. Use this option to quarantine the detected malicious file in a secure location.
UNQUARANTINE_FILE. Use this option to enable the Cybereason platform to remove a file from quarantine. This option is available in version 20.1.120 and later.
BLOCK_FILE. Use this to enable Application Control to block the file(s) associated with the Malop when it they are detected in the future.
KILL_PREVENT_UNSUSPEND. Use this option to prevent detected ransomware from running on the machine.
UNSUSPEND_PROCESS. Use this option to prevent a file associated with ransomware.
ISOLATE_MACHINE: Use this option to isolate a specific machine.


.EXAMPLE
Invoke-RemediateItem -MalopID "11.2718161727221199870" -InitiatorUserName "admin@yourserver.com" -MachineID "-1632138521.1198775089551518743" -ActionType KILL_PROCESS
# This example remediates a process by killing it after it was discovered by a Malop

.EXAMPLE
Invoke-RemediateItem -InitiatorUserName "admin@yourserver.com" -MachineID "-1632138521.1198775089551518743" -TargetID "-2095200899.6557717220054083334" -ActionType KILL_PROCESS
# This example remediates a process that was not involved in a Malop


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None


.LINK
https://nest.cybereason.com/documentation/api-documentation/all-versions/remediate-items#remediatemalops
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
Function Invoke-RemediateItem {
    [CmdletBinding()]
        param(
            [Parameter(
                ParameterSetName='MalopID',
                Mandatory=$True,
                ValueFromPipeline=$False)]  # End Parameter
            [Alias('Malop','Id')]
            [String]$MalopID,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Define the Cybereason user name for the user performing the remediation`n[E] EXAMPLE: admin@cyberason.com")]  # End Parameter
            [Alias('User','Username','Initiator')]
            [String]$InitiatorUserName,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Enter the unique GUID number of the machine. NOTE: This is different from the sensor ID (pylumID) value.`n[E] EXAMPLE: -1632138521.1198775089551518743")]  # End Parameter
            [Int64]$MachineId,

            [Parameter(
                ParameterSetName='TargetID',
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] The unique GUID for the process or file to remediate. You can find this GUID in the response when you perform an investigation query for a process. Note that using the targetId parameter is supported only for processes (the KILL_PROCESS action) and files (the QUARANTINE_FILE or UNQUARANTINE_FILE action). If you use the UNQUARANTINE_FILE action, the targetId (GUID) value is different than the GUID of the original file for the QUARANTINE_FILE action. You can find this GUID for the quarantined file by running a query with the Quarantine File Element.`n[E] EXAMPLE: null")]
            [String]$TargetID,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False)]  # End Parameter
            [ValidateSet('KILL_PROCESS','DELETE_REGISTRY_KEY','QUARANTINE_FILE','UNQUARANTINE_FILE','BLOCK_FILE','KILL_PREVENT_UNSUSPEND','UNSUSPEND_PROCESS','ISOLATE_MACHINE')]
            [String]$ActionType
        )  # End param


    $Obj = @()
    Write-Verbose "Validating -InitiatorUserName parameter is in email address format"
    Try 
    {
    
        $Null = [MailAddress]$InitiatorUserName
    
    }  # End Try
    Catch 
    {

        Throw "[x] The username you defined, $InitiatorUserName, is not a valid email address."
        
    }  # End Catch

    $Uri = "https://" + $Server + ":" + $Port + "/rest/remediate"

    Switch ($PSBoundParameters.Keys)
    {

        'MalopID' {

            $JsonData = '{"malopId":' + $MalopID + ',"initiatorUserName":' + $InitiatorUserName + ',"actionsByMachine":{' + $MachineId + ':[{"actionType":' + $ActionType + '}]}}'
        
        }  # End Switch MalopID

        'TargetID' {

            $JsonData = '{"initiatorUserName":' + $InitiatorUserName + ',"actionsByMachine":{' + $MachineId + ':[{"targetId":' + $TargetID + ',"actionType":' + $ActionType + '}]}}'

        }  # End Switch TargetID

    }  # End Switch
    
    Write-Verbose "Sending request to $Uri"
    $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData -WebSession $Session
    $Response.Content | ConvertFrom-Json | `
        ForEach-Object {
                $MalopId = ($_.malopId | Out-String).Trim()
                $RemediationId = ($_.remediationId | Out-String).Trim()
                $Start = Get-Date -Date ($_.start)
                $End = Get-Date ($_.end)
                $InitiatingUser = ($_.initiatingUser | Out-String).Trim()
                $MachineId = ($_.statusLog.machineID | Out-String).Trim()
                $TargetId = ($_.statusLog.targetId | Out-String).Trim()
                $Status = ($_.statusLog.status | Out-String).Trim()
                $ActionType = ($_.statusLog.actionType | Out-String).Trim()
                $ErrorMessage = $_.statusLog.error
                $TimeStamp = Get-Date -Date ($_.statusLog.timestamp)

                $Obj += New-Object -TypeName PSObject -Property @{malopId=$MalopId; remediationId=$RemediationId; Start=$Start; End=$End; initiatingUser=$InitiatingUser; MachineId=$MachineId; TargetId=$TargetId; Status=$Status; ActionType=$ActionType; TimeStamp=$TimeStamp; Error=$ErrorMessage} 

        }  # End ForEach-Object

    $Obj

}  # End Function Invoke-CybereasonRemediateItem


<#
.SYNOPSIS
This cmdlet is used too return details on the progress of a specific remediation operation.


.DESCRIPTION
Returns details on the progress of a specific remediation operation.


.PARAMETER Username
The Cybereason user name of the user performing the remediation operation.

.PARAMETER MalopID
The unique Malop ID for the Malop for which you are performing remediation.

.PARAMETER RemediationID
This parameter defines the Cybereason remediation Id to check the progress of. The remediation ID returned in a previous remediation request. For details on finding this remediation ID, see https://nest.cybereason.com/api-documentation/all-versions/APIReference/RemediationAPI/remediateMalop.html#remediate-items.


.EXAMPLE
Get-CybereasonRemediationProgress -Username 'admin@cyberason.com' -MalopID '11.2718161727221199870' -RemediationID '86f3faa1-bac0-4a17-9192-9d106b734664'
# This example gets the current status on a Malop that was remediated by the user admin@cyberason.com


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None


.LINK
https://nest.cybereason.com/documentation/api-documentation/all-versions/check-remediation-progress
https://nest.cybereason.com/api-documentation/all-versions/APIReference/RemediationAPI/remediateMalop.html#remediate-items
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
Function Get-CybereasonRemediationProgress {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Enter the username you are querying to view the status of their Malops request `n[E] EXAMPLE: admin@cybereason.com")]  # End Parameter
            [String]$Username,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Enter the Malops ID you are querying to view the progress of in this query `n[E] EXAMPLE: 11.2718161727221199870")]  # End Parameter
            [String]$MalopID,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Enter the Remediation ID you are querying to view the progress of the request `n[E] EXAMPLE: 86f3faa1-bac0-4a17-9192-9d106b734664")]  # End Parameter
            [String]$RemediationID
        )  # End param


    $Obj = @()
    Write-Verbose "Validating -InitiatorUserName parameter is in email address format"
    Try 
    {
        
        $Null = [MailAddress]$InitiatorUserName
       
    }  # End Try
    Catch 
    {
    
        Throw "[x] The username you defined, $InitiatorUserName, is not a valid email address."
            
    }  # End Catch
    
    $Uri = "https://" + $Server + ":" + $Port + "/rest/remediate/progress/" + $Username + "/" + $MalopID + "/" + $RemediationID 

    $Response = Invoke-WebRequest -Method GET -ContentType 'application/json' -Uri $Uri -WebSession $Session

    $Response.Content | ConvertFrom-Json | `
    ForEach-Object {
        $MalopId = ($_.malopId | Out-String).Trim()
        $RemediationId = ($_.remediationId | Out-String).Trim()
        $Start = Get-Date -Date ($_.start)
        $End = Get-Date ($_.end)
        $InitiatingUser = ($_.initiatingUser | Out-String).Trim()
        $MachineId = ($_.statusLog.machineID | Out-String).Trim()
        $TargetId = ($_.statusLog.targetId | Out-String).Trim()
        $Status = ($_.statusLog.status | Out-String).Trim()
        $ActionType = ($_.statusLog.actionType | Out-String).Trim()
        $ErrorMessage = $_.statusLog.error
        $TimeStamp = Get-Date -Date ($_.statusLog.timestamp)

        $Obj += New-Object -TypeName PSObject -Property @{malopId=$MalopId; remediationId=$RemediationId; Start=$Start; End=$End; initiatingUser=$InitiatingUser; MachineId=$MachineId; TargetId=$TargetId; Status=$Status; ActionType=$ActionType; TimeStamp=$TimeStamp; Error=$ErrorMessage} 

    }  # End ForEach-Object

    $Obj
    
}  # End Function Get-CybereasonRemediationProgress

<#
.SYNOPSIS 
This cmdlet aborts a remediation operation on a specific Malop.


.DESCRIPTION
This aborts a remediation operation for the Malop and Remediation ID you define


.PARAMETER MalopID
The unique Malop ID for the Malop for which you are performing remediation.

.PARAMETER RemediationID
This parameter defines the Cybereason remediation Id to check the progress of. The remediation ID returned in a previous remediation request. For details on finding this remediation ID, see https://nest.cybereason.com/api-documentation/all-versions/APIReference/RemediationAPI/remediateMalop.html#remediate-items.


.EXAMPLE
Stop-CybereasonMalopRemediation -MalopID '11.2718161727221199870' -RemediationID '86f3faa1-bac0-4a17-9192-9d106b734664'
# This example aborts the remediation action take on the defined Malop


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None


.LINK
https://nest.cybereason.com/documentation/api-documentation/all-versions/abort-malop-remediation
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
Function Stop-CybereasonMalopRemediation {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Enter the Malops ID you are querying to view the progress of in this query `n[E] EXAMPLE: 11.2718161727221199870")]  # End Parameter
            [String]$MalopID,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Enter the Remediation ID you are querying to view the progress of the request `n[E] EXAMPLE: 86f3faa1-bac0-4a17-9192-9d106b734664")]  # End Parameter
            [String]$RemediationID
        )  # End parm

    $Uri = "https://" + $Server + ":" + $Port + "/rest/remediate/abort/" + $MalopID + "/" + $RemediationID 

    $Response = Invoke-WebRequest -Method POST -ContentType 'application/json' -Uri $Uri -WebSession $Session

    $Response.Content | ConvertFrom-Json | `
    ForEach-Object {
        $MalopId = ($_.malopId | Out-String).Trim()
        $RemediationId = ($_.remediationId | Out-String).Trim()
        $Start = Get-Date -Date ($_.start)
        $End = Get-Date ($_.end)
        $InitiatingUser = ($_.initiatingUser | Out-String).Trim()
        $MachineId = ($_.statusLog.machineID | Out-String).Trim()
        $TargetId = ($_.statusLog.targetId | Out-String).Trim()
        $Status = ($_.statusLog.status | Out-String).Trim()
        $ActionType = ($_.statusLog.actionType | Out-String).Trim()
        $ErrorMessage = $_.statusLog.error
        $TimeStamp = Get-Date -Date ($_.statusLog.timestamp)

        $Obj += New-Object -TypeName PSObject -Property @{malopId=$MalopId; remediationId=$RemediationId; Start=$Start; End=$End; initiatingUser=$InitiatingUser; MachineId=$MachineId; TargetId=$TargetId; Status=$Status; ActionType=$ActionType; TimeStamp=$TimeStamp; Error=$ErrorMessage} 

    }  # End ForEach-Object

    $Obj

}  # End Function Stop-CybereasonMalopRemediation

<#
.SYNOPSIS 
This cmdlet retrieves details about remediation actions performed on a particular Malop.


.DESCRIPTION
This retrieves details about remediation actions performed on a particular Malop you define


.PARAMETER MalopID
The unique Malop ID for the Malop for which you are performing remediation.


.EXAMPLE
Get-CybereasonRemediationStatus -MalopID '11.2718161727221199870'
# This example gets the current status for the defined Malop


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None


.LINK
https://nest.cybereason.com/documentation/api-documentation/all-versions/get-remediation-statuses
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
Function Get-CybereasonRemediationStatus {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Enter the Malops ID you are querying to view the progress of in this query `n[E] EXAMPLE: 11.2718161727221199870")]  # End Parameter
            [String]$MalopID
        )  # End param


    $Uri = "https://" + $Server + ":" + $Port + "/rest/remediate/status/" + $MalopID

    $Response = Invoke-WebRequest -Method GET -ContentType 'application/json' -Uri $Uri -WebSession $Session
    
    $Response.Content | ConvertFrom-Json | `
    ForEach-Object {
        $MalopId = ($_.malopId | Out-String).Trim()
        $RemediationId = ($_.remediationId | Out-String).Trim()
        $Start = Get-Date -Date ($_.start)
        $End = Get-Date ($_.end)
        $InitiatingUser = ($_.initiatingUser | Out-String).Trim()
        $MachineId = ($_.statusLog.machineID | Out-String).Trim()
        $TargetId = ($_.statusLog.targetId | Out-String).Trim()
        $Status = ($_.statusLog.status | Out-String).Trim()
        $ActionType = ($_.statusLog.actionType | Out-String).Trim()
        $ErrorMessage = $_.statusLog.error
        $TimeStamp = Get-Date -Date ($_.statusLog.timestamp)
    
        $Obj += New-Object -TypeName PSObject -Property @{malopId=$MalopId; remediationId=$RemediationId; Start=$Start; End=$End; initiatingUser=$InitiatingUser; MachineId=$MachineId; TargetId=$TargetId; Status=$Status; ActionType=$ActionType; TimeStamp=$TimeStamp; Error=$ErrorMessage} 
    
    }  # End ForEach-Object
    
    $Obj

}  # End Function Get-CybereasonRemediationStatus


<#
.SYNOPSIS
This cmdlet retrieves a list of all rules for isolating specific machines.


.DESCRIPTION
Retrieves a list of all rules for isolating specific machines.


.EXAMPLE
Get-CybereasonIsolationRules
# This example retrieves a list of all rules for isolating specific machines


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None


.LINK
https://nest.cybereason.com/api-documentation/all-versions/APIReference/IsolationAPI/retrieveRules.html#getisolationrules
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
Function Get-CybereasonIsolationRules {
    [CmdletBinding()]
        param()

    $Obj = @()
    $Uri = "https://" + $Server + ":" + $Port + "/rest/settings/isolation-rule"
    $Response = Invoke-WebRequest -Method GET -ContentType 'application/json' -Uri $Uri -WebSession $Session
    
    Try 
    {

        $Response.Content | ConvertFrom-Json | `
        ForEach-Object {
            $RuleId = ($_.ruleId | Out-String).Trim()
            $IpAddress = ($_.ipAddress | Out-String).Trim()
            $IpAddressString = ($_.ipAddressString | Out-String).Trim()
            $Domain = ($_.domain | Out-String).Trim()
            $PortNumber = ($_.port | Out-String).Trim()
            $Direction = ($_.direction | Out-String).Trim()
            $LastUpdated = Get-Date -Date ($_.lastUpdated)
            $Blocking = ($_.blocking | Out-String).Trim()
        
            $Obj += New-Object -TypeName PSObject -Property @{RuleId=$RuleId; IPAddress=$IpAddress; IPAddressString=$ipAddressString; Domain=$Domain; Port=$PortNumber; Direction=$Direction; LastUpdated=$LastUpdated; Blocking=$Blocking} 
        
        }  # End ForEach-Object
        
        $Obj

    }  # End Try
    Catch 
    {
        
        Write-Output "No isolation rules were found"

    }  # End Catch

}  # End Function Get-CybereasonIsolationRules


<#
.SYNOPSIS
This cmdlet is used to create an isolation exception rule.


.DESCRIPTION
Creates an isolation exception rule.


.PARAMETER IPAddressString
The IP address of the machine to which the rule applies.

.PARAMETER PortNumber
Optional if the ipAddressString parameter exists. The port by which Cybereason communicates with an isolated machine, according to the rule.

.PARAMETER Blocking
States whether communication with the given IP or port is allowed. Set to true if communication is blocked.

.PARAMETER Direction
The direction of the allowed communication. Values include ALL, INCOMING, or OUTGOING.


.EXAMPLE
New-CybereasonIsolationRule -IPAddressString '123.45.67.89' -PortNumber 8443 -Blocking -Direction ALL
# This example creates a new isolation rule that blocks All communication to 123.45.67.89


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None


.LINK
https://nest.cybereason.com/api-documentation/all-versions/APIReference/IsolationAPI/createRule.html#createisolationrule
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
Function New-CybereasonIsolationRule {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Enter the IP Address of the machine for which the rule should apply.`n[E] EXAMPLE: 123.45.67.89")]  # End Parameter
            [String[]]$IpAddressString,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [ValidateRange(1,65535)]
            [Int16]$PortNumber,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]
             [Switch][Bool]$Blocking,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Define the direction the rule should be applied too.`n[E] EXAMPLE: INCOMING")]  # End Parameter
            [ValidateSet('ALL','INCOMING','OUTGOING')]
            [String]$Direction
        )  # End param

    $Obj = @()
    If ($Blocking.IsPresent)
    {

        $Block = 'true'

    }  # End If
    Else 
    {

        $Block = 'false'

    }  # End If

    If ($IpAddressString.Length -gt 0)
    {

        $StringOne = '"ipAddressString":' + $IpAddressString

    }  # End If

    If ($PortNumber.Length -gt 0)
    {

        $StringTwo = ',"port":' + $PortNumber

    }  # End If

    $Uri = "https://" + $Server + ":" + $Port + "/rest/settings/isolation-rule"

    $JsonData = '{' + $StringOne + $StringTwo + ',"blocking":"' + $Block + '","direction":' + $Direction + '}'

    $Response = Invoke-WebRequest -Method POST -ContentType 'application/json' -Uri $Uri -WebSession $Session -Headers @{Cookie="JSESSIONID=$JSESSIONID"} -Body $JsonData

        $Response.Content | ConvertFrom-Json | `
        ForEach-Object {
            $RuleId = ($_.ruleId | Out-String).Trim()
            $IpAddress = ($_.ipAddress | Out-String).Trim()
            $IpAddressString = ($_.ipAddressString | Out-String).Trim()
            $Domain = ($_.domain | Out-String).Trim()
            $PortNumber = ($_.port | Out-String).Trim()
            $Direction = ($_.direction | Out-String).Trim()
            $LastUpdated = Get-Date -Date ($_.lastUpdated)
            $Blocking = ($_.blocking | Out-String).Trim()
                    
            $Obj += New-Object -TypeName PSObject -Property @{RuleId=$RuleId; IPAddress=$IpAddress; IPAddressString=$ipAddressString; Domain=$Domain; Port=$PortNumber; Direction=$Direction; LastUpdated=$LastUpdated; Blocking=$Blocking} 
                
        }  # End ForEach-Object
         
    $Obj

}  # End Function New-CybereasonIsolationRule


<#
.SYNOPSIS
This cmdlet is used to updates an isolation exception rule.


.DESCRIPTION
Updates an isolation exception rule.


.PARAMETER RuleID
A unique identifier for the rule

.PARAMETER IPAddressString
The IP address of the machine to which the rule applies.

.PARAMETER PortNumber
Optional if the ipAddressString parameter exists. The port by which Cybereason communicates with an isolated machine, according to the rule.

.PARAMETER Blocking
States whether communication with the given IP or port is allowed. Set to true if communication is blocked.

.PARAMETER Direction
The direction of the allowed communication. Values include ALL, INCOMING, or OUTGOING.


.EXAMPLE 
Set-CybereasonIsolationRule -RuleID "5a7b2e95e4b082f2e909a4f3" -IPAddressString '123.45.67.89' -PortNumber 8443 -Blocking -Direction ALL
# This example creates a new isolation rule that blocks All communication to 123.45.67.89


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None


.LINK
https://nest.cybereason.com/api-documentation/all-versions/APIReference/IsolationAPI/updateRule.html#updateisolationrule
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
Function Set-CybereasonIsolationRule {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False)]  # End Parameter
            [String]$RuleID,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Enter the IP Address of the machine for which the rule should apply.`n[E] EXAMPLE: 123.45.67.89")]  # End Parameter
            [String]$IpAddressString,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [ValidateRange(1,65535)]
            [Int16]$PortNumber,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]
             [Switch][Bool]$Blocking,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Define the direction the rule should be applied too.`n[E] EXAMPLE: INCOMING")]  # End Parameter
            [ValidateSet('ALL','INCOMING','OUTGOING')]
            [String]$Direction,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Using the Tick format, define the last update value to specifiy the rule you wish to modify the info on `n[E] EXAMPLE: 1525594605852")]  # End Parameter
            [String]$LastUpdated
        )  # End param

    $Obj = @()
    If ($Blocking.IsPresent)
    {

        $Block = 'true'
        $StringThree = ',"blocking":"' + $Block + '"'

    }  # End If
    Else 
    {

        $Block = 'false'
        $StringThree = ',"blocking":"' + $Block + '"'

    }  # End If

    $Uri = "https://" + $Server + ":" + $Port + "/rest/settings/isolation-rule"

    If ($IpAddressString.Length -gt 0)
    {

        $StringOne = ',"ipAddressString":' + $IpAddressString

    }  # End If

    If ($PortNumber.Length -gt 0)
    {

        $StringTwo = ',"port":' + $PortNumber

    }  # End If

    If ($Direction.Length -gt 0)
    {

        $StringFour = ',"direction":' + $Direction

    }  # End If

    If ($LastUpdated.Length -gt 0)
    {

        $StringFive = ',"lastUpdated":' + $LasUpdated

    }  # End If
    
    $JsonData = '{"ruleId":' + $RuleID + $StringOne + $StringTwo + $StringThree + $StringFour + $StringFive + '}'
    
    $Response = Invoke-WebRequest -Method PUT -ContentType 'application/json' -Uri $Uri -WebSession $Session -Body $JsonData

    $Response.Content | ConvertFrom-Json | `
    ForEach-Object {
        $RuleId = ($_.ruleId | Out-String).Trim()
        $IpAddress = ($_.ipAddress | Out-String).Trim()
        $IpAddressString = ($_.ipAddressString | Out-String).Trim()
        $Domain = ($_.domain | Out-String).Trim()
        $PortNumber = ($_.port | Out-String).Trim()
        $Direction = ($_.direction | Out-String).Trim()
        $LastUpdated = Get-Date -Date ($_.lastUpdated)
        $Blocking = ($_.blocking | Out-String).Trim()

        $Obj += New-Object -TypeName PSObject -Property @{RuleId=$RuleId; IPAddress=$IpAddress; IPAddressString=$ipAddressString; Domain=$Domain; Port=$PortNumber; Direction=$Direction; LastUpdated=$LastUpdated; Blocking=$Blocking} 

    }  # End ForEach-Object 

    $Obj

}  # End Function Set-CybereasonIsolationRule


<#
.SYNOPSIS
This cmdlet is used too delete an isolation exception rule.


.DESCRIPTION
Deletes an isolation exception rule.


.PARAMETER RuleID
A unique identifier for the rule

.PARAMETER IPAddressString
The IP address of the machine to which the rule applies.

.PARAMETER PortNumber
Optional if the ipAddressString parameter exists. The port by which Cybereason communicates with an isolated machine, according to the rule.

.PARAMETER Blocking
States whether communication with the given IP or port is allowed. Set to true if communication is blocked.

.PARAMETER Direction
The direction of the allowed communication. Values include ALL, INCOMING, or OUTGOING.

.PARAMETER LastUpdate
The epoch timestamp for the last update time for the rule.


.EXAMPLE
Remove-CybereasonIsolationRule -RuleID '5859b3d0ae8eeb920e9d2f4e' -IPAddressString '1.1.1.1' -PortNumber 8443 -Direction ALL -LastUpdated 1525594605852
# This example deletes the isolation rule that is blocking all traffic to 1.1.1.1

.EXAMPLE
Remove-CybereasonIsolationRule -RuleID '5859b3d0ae8eeb920e9d2f4e' -IPAddressString '10.10.10.10' -PortNumber 8443 -Blocking -Direction OUTGOING -LastUpdated 1525594605852
# This example deletes the rule ID that has IP address 10.10.10.10 outbound traffic blocked


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None


.LINK
https://nest.cybereason.com/api-documentation/all-versions/APIReference/IsolationAPI/deleteRule.html#deleteisolationrule
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
Function Remove-CybereasonIsolationRule {
    [CmdletBinding()]
        param(
        [Parameter(
            Mandatory=$True,
            ValueFromPipeline=$False)]  # End Parameter
        [String]$RuleID,

        [Parameter(
            Mandatory=$False,
            ValueFromPipeline=$False,
            HelpMessage="`n[H] Enter the IP Address of the machine in the rule to delete.`n[E] EXAMPLE: 123.45.67.89")]  # End Parameter
        [String]$IpAddressString,

        [Parameter(
            Mandatory=$False,
            ValueFromPipeline=$False)]  # End Parameter
        [ValidateRange(1,65535)]
        [Int16]$PortNumber,

        [Parameter(
            Mandatory=$False,
            ValueFromPipeline=$False)]
         [Switch][Bool]$Blocking,

        [Parameter(
            Mandatory=$False,
            ValueFromPipeline=$False,
            HelpMessage="`n[H] Define the direction the rule should be applied too.`n[E] EXAMPLE: INCOMING")]  # End Parameter
        [ValidateSet('ALL','INCOMING','OUTGOING')]
        [String]$Direction,

        [Parameter(
            Mandatory=$True,
            ValueFromPipeline=$False,
            HelpMessage="`n[H] Using the Tick format, define the last update value to specifiy the rule you wish to modify the info on `n[E] EXAMPLE: 1525594605852")]  # End Parameter
        [String]$LastUpdated)


    $Uri = "https://" + $Server + ":" + $Port + "/rest/settings/isolation-rule/delete"

    If ($Blocking.IsPresent)
    {
    
        $Block = 'true'
        $StringThree = ',"blocking":"' + $Block + '"'
    
    }  # End If
    Else 
    {
    
        $Block = 'false'
        $StringThree = ',"blocking":"' + $Block + '"'
    
    }  # End If

    If ($IpAddressString.Length -gt 0)
    {
    
        $StringOne = ',"ipAddressString":' + $IpAddressString
    
    }  # End If
    
    If ($PortNumber.Length -gt 0)
    {
    
        $StringTwo = ',"port":' + $PortNumber
    
    }  # End If
    
    If ($Direction.Length -gt 0)
    {
    
        $StringFour = ',"direction":' + $Direction
    
    }  # End If
    
    If ($LastUpdated.Length -gt 0)
    {
    
        $StringFive = ',"lastUpdated":' + $LasUpdated
    
    }  # End If
        
    $JsonData = '{"ruleId":' + $RuleID + $StringOne + $StringTwo + $StringThree + $StringFour + $StringFive + '}'

    $Response = Invoke-WebRequest -Method POST -ContentType 'application/json' -Uri $Uri -WebSession $Session -Body $JsonData
    $Response.Content | ConvertFrom-Json

}  # End Function Remove-CybereasonIsolationRule