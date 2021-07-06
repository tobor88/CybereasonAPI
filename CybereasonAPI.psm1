<#
.SYNOPSIS
This cmdlet is used to authenticate to the Cybereason API. Once this is done a global $CybereasonSession variable is created that will be used for all other cmdlets in this module.


.DESCRIPTION
This cmdlet creates a $CybereasonSession variable that will be used with all the other cmdlets in this module to authenticate requests made to the Cybereason API.


.PARAMETER Server
This parameter defines the server IP address or domain name your Cybereason server is running on

.PARAMETER Port
This parameter is used to define the port your Cybereason server is on. This is usually 443 or 8443. The default value is 443.

.PARAMETER Username
This is the email address you use to sign into Cybereason

.PARAMETER Passwd
This is the password you use to sign into your Cybereason account. The session history gets cleared to attempt preventing the password from appearing in the session logs. This does not clear the events logs. I suggest only letting administrators view the PowerShell event logs.

.PARAMETER Authenticator
This parameter is for NON-API Cybereason users to authenticate to Cyberason using Two Factor Authentication (TFA). When used, the only cmdlet in this module that will work is Get-CybereasonThreatIntel


.EXAMPLE
Connect-CybereasonAPI -Server 123.45.67.78 -Port 8443 -Username api-user@cyberason.com -Passwd "Password123!" -ClearHistory
# This example authenticates to the Cybereason API and creates a $CybereasonSession variable to be used by other cmdlets. This also clears the PowerShell command history of the current session as well as the HistorySavePath file value.

.EXAMPLE
Connect-CybereasonAPI -Server 123.45.67.78 -Port 443 -Username admin-user@cyberason.com -Passwd "Password123!" -Authenticator 123123 -ClearHistory
# IMPORTANT: Only non-api users are able to use Two Factor Authentication (TFA). This prevents organization level cmdlets from working. Only Get-CybereasonThreatIntel works after authenticating with a non-API user


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
https://writeups.osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
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
                HelpMessage="`n[H] Enter the IP address or hostname of your Cybereason server. DO NOT include the port `n[E] EXAMPLE: 10.0.0.1`n[E] EXAMPLE: asdf.cybereason.com")]
            [ValidateNotNullOrEmpty()]
            [String]$Server,

            [Parameter(
                Position=3,
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [ValidateRange(1,65535)]
            [String]$Port = "443",

            [Parameter(
                Position=4,
                Mandatory=$False,
                ValueFromPipeline=$False,  # End Parameter
                HelpMessage="`n[H] Enter the code from your authenticator app `n[E] EXAMPLE: 123456")]
            [String]$Authenticator,

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
    If ($Authenticator)
    {

        $Body = @{
            username="$Username"
            password="$Passwd"
            totpCode="$Authenticator"
        }  # End Body

    }  # End If

    Write-Verbose "Sending request to $Uri"
    $Results = Invoke-WebRequest -Method POST -Uri $Uri -ContentType "application/x-www-form-urlencoded" -Body $Body -SessionVariable 'CybereasonSession'

    If ($Results.StatusCode -eq '200')
    {

        Write-Output "[*] Successfully created an authenticated session to the Cybereason API."

    }  # End If
    Else
    {

        Write-Warning "[!] Status code returned was not a value of 200. Value received is below"
        $Results.StatusCode
        $Results

    }  # End Else

    $Global:CybereasonSession = $CybereasonSession
    $Global:Server = $Server
    $Global:Port = $Port

    If ($ClearHistory.IsPresent)
    {

        Write-Output "[*] Using the Clear-History command to clear the current PowerShell sessions command history"
        Clear-History

        Write-Output "[*] Deleing the PowerShell HistorySavePath file which stores a copy of the previous command history"
        Remove-Item (Get-PSReadlineOption).HistorySavePath

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
https://writeups.osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
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
Get-CybereasonReputation -Path C:\Windows\Temp\CybereasonRepuations.csv
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
https://writeups.osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
Function Get-CybereasonReputation {
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
        Invoke-RestMethod -URI $Uri -WebSession $CybereasonSession -Headers @{charset='utf-8'} -ContentType "application/json" -Method GET -OutFile "$Path"

    }  # End If
    Else
    {

        Write-Verbose "Returning CSV formatted results to window"
        Invoke-RestMethod -URI $Uri -WebSession $CybereasonSession -ContentType "application/json" -Method GET

    }  # End Else

}  # End Function Get-CybereasonReputation


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
Set-CybereasonReputation -Keys '1.1.1.1' -Modify Whitelist -Action Add -PreventExecution False
# This example sets the Cybereason repuations of IP address 1.1.1.1 by adding it to the whitelist. Because this is an IP address the -PreventExecution parameter needs to be false. This will be modified automatically in the script if set incorrectly.

.EXAMPLE
Set-CybereasonReputation -Keys 'maliciousdomain.com' -Modify Blacklist -Action Add -PreventExecution False
# This example sets the Cybereason repuations of domain maliciousdomain.com by adding it to the blacklist. Because this is not a file hash the -PreventExecution parameter needs to be false. This will be modified automatically in the script if set incorrectly.

.EXAMPLE
Set-CybereasonReputation -Keys 'badguy.com','badperson.com' -Modify Blacklist -Action Add -PreventExecution False
# This example sets the Cybereason repuations of domain badguy.com and badperson.com by adding them to the blacklist. Because this is not a file hash the -PreventExecution parameter needs to be false. This will be modified automatically in the script if set incorrectly.

.EXAMPLE
Set-CybereasonReputation -Keys 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' -Modify 'Blacklist' -Action 'Add' -PreventExecution 'True'
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
https://writeups.osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
Function Set-CybereasonReputation {
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
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData -WebSession $CybereasonSession
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
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData -WebSession $CybereasonSession
            $Response.Content | ConvertFrom-Json

        }  # End ForEach

    }  # End Else

}  # End Function Set-CybereasonReputation


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
System.Object[]


.LINK
https://nest.cybereason.com/documentation/api-documentation/all-versions/remediate-items#remediatemalops
https://roberthsoborne.com
https://writeups.osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
Function Invoke-RemediateItem {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
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
    $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData -WebSession $CybereasonSession
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
https://writeups.osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
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

    $Response = Invoke-WebRequest -Method GET -ContentType 'application/json' -Uri $Uri -WebSession $CybereasonSession

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
https://writeups.osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
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

    $Response = Invoke-WebRequest -Method POST -ContentType 'application/json' -Uri $Uri -WebSession $CybereasonSession

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
https://writeups.osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
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

    $Response = Invoke-WebRequest -Method GET -ContentType 'application/json' -Uri $Uri -WebSession $CybereasonSession

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
Get-CybereasonIsolationRule
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
https://writeups.osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
Function Get-CybereasonIsolationRule {
    [CmdletBinding()]
        param()

    $Obj = @()
    $Uri = "https://" + $Server + ":" + $Port + "/rest/settings/isolation-rule"
    $Response = Invoke-WebRequest -Method GET -ContentType 'application/json' -Uri $Uri -WebSession $CybereasonSession

    If ($Response.StatusCode -eq 200)
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

    }
    Else
    {

        Write-Output "[*] No isolation rules were found or access was denied. Try authenticating with a non-api user if you believe you should have this access."
        $Response

    }  # End Catch

}  # End Function Get-CybereasonIsolationRule


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
https://writeups.osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
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

        $StringOne = '"ipAddressString":"' + $IpAddressString + '"'

    }  # End If

    If ($PortNumber.Length -gt 0)
    {

        $StringTwo = ',"port":' + $PortNumber

    }  # End If

    $Uri = "https://" + $Server + ":" + $Port + "/rest/settings/isolation-rule"

    $JsonData = '{' + $StringOne + $StringTwo + ',"blocking":"' + $Block + '","direction":"' + $Direction + '"}'

    $Response = Invoke-WebRequest -Method POST -ContentType 'application/json' -Uri $Uri -WebSession $CybereasonSession -Body $JsonData

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
https://writeups.osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
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

        $StringOne = ',"ipAddressString":"' + $IpAddressString + '"'

    }  # End If

    If ($PortNumber.Length -gt 0)
    {

        $StringTwo = ',"port":' + $PortNumber

    }  # End If

    If ($Direction.Length -gt 0)
    {

        $StringFour = ',"direction":"' + $Direction + '"'

    }  # End If

    If ($LastUpdated.Length -gt 0)
    {

        $StringFive = ',"lastUpdated":' + $LasUpdated

    }  # End If

    $JsonData = '{"ruleId":"' + $RuleID + '"' + $StringOne + $StringTwo + $StringThree + $StringFour + $StringFive + '}'

    $Response = Invoke-WebRequest -Method PUT -ContentType 'application/json' -Uri $Uri -WebSession $CybereasonSession -Body $JsonData

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
https://writeups.osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
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

        $StringOne = ',"ipAddressString":"' + $IpAddressString + '"'

    }  # End If

    If ($PortNumber.Length -gt 0)
    {

        $StringTwo = ',"port":' + $PortNumber

    }  # End If

    If ($Direction.Length -gt 0)
    {

        $StringFour = ',"direction":"' + $Direction + '"'

    }  # End If

    If ($LastUpdated.Length -gt 0)
    {

        $StringFive = ',"lastUpdated":' + $LasUpdated

    }  # End If

    $JsonData = '{"ruleId":' + $RuleID + $StringOne + $StringTwo + $StringThree + $StringFour + $StringFive + '}'

    $Response = Invoke-WebRequest -Method POST -ContentType 'application/json' -Uri $Uri -WebSession $CybereasonSession -Body $JsonData
    $Response.Content | ConvertFrom-Json

}  # End Function Remove-CybereasonIsolationRule


<#
.SYNOPSIS
This cmdlet returns a count of each type of malware.


.DESCRIPTION
Returns a count of each type of malware. When sending this request, there may be a delay in returning a response, depending on how much data and activity is in your system. Ensure you do not send this request multiple times while waiting for response as this may cause unexpected results and performance issues in your environment. If you want to return fewer types of malware, you can remove the necessary filters object from the template above. In addition, if you are trying to retrieve types of malware other than the Needs Attention type, you must add multiple objects in the filters object as seen above.


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None


.LINK
https://nest.cybereason.com/documentation/api-documentation/all-versions/get-malware-counts#getmalwarecounts
https://roberthsoborne.com
https://writeups.osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
Function Get-CybereasonMalwareCount {
    [CmdletBinding()]
        param()  # End param


    $Uri = 'https://' + $Server + ':' + $Port + '/rest/malware/counts'
    $JsonData = '{"compoundQueryFilters":[{"filters":[{"fieldName":"needsAttention","operator":"Is","values":[true]}],"filterName":"needsAttention"},{"filters":[{"fieldName":"type","operator":"Equals","values":["KnownMalware"]},{"fieldName":"needsAttention","operator":"Is","values":[false]}],"filterName":"KnownMalware"},{"filters":[{"fieldName":"type","operator":"Equals","values":["UnknownMalware"]},{"fieldName":"needsAttention","operator":"Is","values":[false]}],"filterName":"UnknownMalware"},{"filters":[{"fieldName":"type","operator":"Equals","values":["FilelessMalware"]},{"fieldName":"needsAttention","operator":"Is","values":[false]}],"filterName":"FilelessMalware"},{"filters":[{"fieldName":"type","operator":"Equals","values":["ApplicationControlMalware"]}],"filterName":"ApplicationControlMalware"}]}'

    Write-Verbose "Sending query to $Uri"
    $Response = Invoke-WebRequest -Method POST -ContentType 'application/json' -Uri $Uri -WebSession $CybereasonSession -Body $JsonData
    $Results = $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty data | Select-Object -ExpandProperty malwareCountFilters

    $TotalCount = ($Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty data).TotalCount
    $Results += New-Object -TypeName PSObject -Property @{Filter='Total'; Count=$TotalCount}

    $Results

}  # End Function Get-CybereasonMalwareCount


<#
.SYNOPSIS
This cmdlet is supported from Cybereason version 17.5 and later. Returns details on malware currently in your environment.


.DESCRIPTION
Returns details on malware currently in your environment.


.PARAMETER MalwareType
This parameter defines the type of malware you wish to return results on

.PARAMETER NeedsAttention
This switch parameter indicates you wish to return results on all malware that needs attention

.PARAMETER All
This switch parameter indicates you wish to return information on all results of the malware type you define

.PARAMETER MalwareAfter
This indicates a timestamp in the form of ticks from which to start a search on malware. This will return info on any malware that occured before the date you define

.PARAMETER MalwareBefore
This indicates a timestamp in the form of ticks from which to start a search on malware. This will return info on any malware that occured after the date you define

.PARAMETER Limit
This parameter defines the amount of results to return. The default value is 25

.PARAMETER Sort
This parameter defines whether to sort the results in Ascending or Descending order. The default value is descending

.PARAMETER Offset
This parameter defines the malware page to start your search from. 0 is the default value which starts your search from the beginning

.PARAMETER CompletedKnownMalware
This switch parameter returns all known malware with a status of done


.EXAMPLE
Get-CybereasonMalwareType -MalwareType KnownMalware -NeedsAttention -Limit 1 -Sort ASC
# This example returns 1 result on all malware that needs attention in ascending order of their occurences

.EXAMPLE
Get-CybereasonMalwareType -MalwareType KnownMalware -All -Limit 25 -Sort DESC -Offset 0
# This example returns up to 25 results on all known malware in descending order

.EXAMPLE
Get-CybereasonMalwareType -MalwareAfter (Get-Date).AddDays(-2).Ticks
# This example returns info on all known malware that occured after a defined date

.EXAMPLE
Get-CybereasonMalwareType -MalwareBefore (Get-Date).AddDays(-2).Ticks
# This example returns info on all known malware that occured before a defined date

.EXAMPLE
Get-CybereasonMalwareType -MalwareType KnownMalware -Status Done -Limit 25 -Sort DESC -Offset 0
# This example returns info on all known malware with a status of done


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None


.LINK
https://nest.cybereason.com/documentation/api-documentation/all-versions/query-malware-types
https://roberthsoborne.com
https://writeups.osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
Function Get-CybereasonMalwareType {
    [CmdletBinding(DefaultParameterSetName='All')]
        param(
            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Define one of the types of Malware you want to query the results of.`n[E] EXAMPLE: RansomwareMalware")]  # End Parameter
            [ValidateSet('KnownMalware','UnknownMalware','FilelessMalware','ApplicationControlMalware','RansomwareMalware')]
            [String]$MalwareType,

            [Parameter(
                ParameterSetName='Status',
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] `n[E] EXAMPLE: Done")]  # End Parameter
            [ValidateSet('Done','Excluded','Detected','Prevented','Remediated','DeleteOnRestart','Quarantined')]
            [String]$Status,

            [Parameter(
                ParameterSetName='MalwareAfter')]  # End Parameter
                [Parameter(
                ParameterSetName='MalwareBefore')]  # End Parameter
            [Parameter(
                ParameterSetName='Status')]  # End Parameter
            [Parameter(
                ParameterSetName='NeedsAttention')]  # End Parameter
            [Switch][Bool]$NeedsAttention,

            [Parameter(
                ParameterSetName='All')]  # End Parameter
            [Switch][Bool]$All,

            [Parameter(
                ParameterSetName='MalwareAfter',
                Position=0,
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Use a timestamp in the form of ticks to discover malware that occured after a certain date and time`n[E] EXAMPLE: 637381353373709085")]  # End Parameter
            [Int64]$MalwareAfter,

            [Parameter(
                ParameterSetName='MalwareBefore',
                Position=0,
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Use a timestamp in the form of ticks to discover malware that occured before a certain date and time`n[E] EXAMPLE: 637381353373709085")]  # End Parameter
            [Int64]$MalwareBefore,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Int32]$Limit = 25,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [ValidateSet('ASC','DESC')]
            [String]$Sort = 'DESC',

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Int32]$Offset = 0

        )  # End param


    $Uri = 'https://' + $Server + ':' + $Port + '/rest/malware/query'

    Switch ($PSBoundParameters.Keys)
    {

        'NeedsAttention' {

            $JsonData = '{"filters": [{"fieldName":"type","operator":"Equals","values":["' + $MalwareType + '"]}],"sortingFieldName":"timestamp","sortDirection":"' + $Sort + '","limit":' + $Limit + ',"offset":' + $Offset + '})'

        }  # End Switch Needs Attention

        'All' {

            $JsonData = '{"filters":[{"fieldName":"type","operator":"Equals","values":["' + $MalwareType + '"]},{"fieldName":"needsAttention","operator":"Is","values":[' + $NeedsAttentionBool + ']}],"sortingFieldName":"timestamp","sortDirection":"' + $Sort + '","limit":' + $Limit + ',"offset":' + $Offset + '})'

        }  # End Switch AllKnownMalware

        'MalwareAfter' {

            $NeedsAttentionBool = 'false'
            If ($NeedsAttention.IsPresent)
            {

                $NeedsAttentionBool = 'true'

            }  # End If

            $JsonData = '{"filters":[{"fieldName":"type","operator": "Equals","values":["' + $MalwareType + '"]},{"fieldName":"needsAttention","operator":"Is","values":[' + $NeedsAttentionBool + ']},{"fieldName":"timestamp","operator":"GreaterOrEqualsTo","values":["timestamp"]}],"sortingFieldName":"timestamp","sortDirection":"' + $Sort + '","limit":' + $Limit + ',"offset":' + $Offset + '})'

        }  # End Switch KnownMalwareFromTime

        'MalwareBefore' {

            $NeedsAttentionBool = 'false'
            If ($NeedsAttention.IsPresent)
            {

                $NeedsAttentionBool = 'true'

            }  # End If

            $JsonData = '{"filters":[{"fieldName":"type","operator": "Equals","values":["' + $MalwareType + '"]},{"fieldName":"needsAttention","operator":"Is","values":[' + $NeedsAttentionBool + ']},{"fieldName":"timestamp","operator":"LessOrEqualsTo","values":["timestamp"]}],"sortingFieldName":"timestamp","sortDirection":"' + $Sort + '","limit":' + $Limit + ',"offset":' + $Offset + '})'

        }  # End Switch KnownMalwareFromTime

        'Status' {

            $NeedsAttentionBool = 'false'
            If ($NeedsAttention.IsPresent)
            {

                $NeedsAttentionBool = 'true'

            }  # End If

            $JsonData = '{"filters":[{"fieldName":"type","operator":"Equals","values":["' + $MalwareType + '"]},{"fieldName":"needsAttention","operator":"Is","values":[' + $NeedsAttentionBool + ']},{"fieldName":"status","operator":"Equals","values":["' + $Status + '"]}],"sortingFieldName":"timestamp","sortDirection":"' + $Sort + '","limit":' + $Limit + ',"offset":' + $Offset + '})'

        }  # End Switch CompletedKnownMalware

    }  # End Switch
    Write-Verbose "Sending query to $Uri"
    $Response = Invoke-WebRequest -Method POST -ContentType 'application/json' -Uri $Uri -WebSession $CybereasonSession -Body $JsonData

    $Results = $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty data

    If ($Results.totalResults -eq 0)
    {

        Write-Output "[*] There were not any results returned"
        $Results

    }  # End If
    Else
    {

        $Results.malwares

    }  # End Else

    If ($Results.hasMoreResults -like 'True')
    {

        Write-Output "[*] More results were found but not all were returned. Raise the -Limit parameters value if you wish to view more"

    }  # End If

}  # End Function Get-CybereasonMalwareType


<#
.SYNOPSIS
This cmdlet is used to retrieve a list of custom detection rules


.DESCRIPTION
Retrieve a list of custom detection rules


.PARAMETER ActiveRules
This switch parameter returns a list of all custom rules currently active in your environment.

.PARAMETER DisabledRules
This switch parameter returns a list of all custom rules currently disabled in your environment.

.PARAMETER RootCauses
Returns a list of all Elements you can use for a root cause for a Malop generated from this custom rule.

.PARAMETER DetectionTypes
Returns a list of all available detection types you can use for the custom detection rule.

.PARAMETER ActivityTypes
Returns a list of all available Malop activity types you can use for the custom detection rule.

.PARAMETER RuleID
Define the rule ID value you wish to view the modificaiton history on

.PARAMETER ModificationHistory
Returns details on modifications made to a custom rule.


.EXAMPLE
Get-CybereasonCustomDetectionRule -ActiveRules
# This eample returns a list of all custom rules currently active in your environment.

.EXAMPLE
Get-CybereasonCustomDetectionRule -DisabledRules
# This eample returns a list of all custom rules currently disabled in your environment.

.EXAMPLE
Get-CybereasonCustomDetectionRule -RootCauses
# This eample returns a list of all Elements you can use for a root cause for a Malop generated from this custom rule.

.EXAMPLE
Get-CybereasonCustomDetectionRule -DetectionTypes
# This eample returns a list of all available detection types you can use for the custom detection rule.

.EXAMPLE
Get-CybereasonCustomDetectionRule -ActivityTypes
# This eample returns a list of all available Malop activity types you can use for the custom detection rule.

.EXAMPLE
Get-CybereasonCustomDetectionRule -RuleID 1582038865368 -ModificationHistory
# This eample returns details on modifications made to a custom rule.


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None


.LINK
https://nest.cybereason.com/documentation/api-documentation/all-versions/add-custom-detection-rules
https://roberthsoborne.com
https://writeups.osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
Function Get-CybereasonCustomDetectionRule {
    [CmdletBinding(DefaultParameterSetName='Active')]
        param(
            [Parameter(
                ParameterSetName='Active')]  # End Parameter
            [Switch][Bool]$Active,

            [Parameter(
                ParameterSetName='Disabled')]  # End Parameter
            [Switch][Bool]$Disabled,

            [Parameter(
                ParameterSetName='RootCauses')]  # End Parameter
            [Switch][Bool]$RootCauses,

            [Parameter(
                ParameterSetName='DetectionTypes')]  # End Parameter
            [Switch][Bool]$DetectionTypes,

            [Parameter(
                ParameterSetName='ActivityTypes')]  # End Parameter
            [Switch][Bool]$ActivityTypes,

            [Parameter(
                ParameterSetName='ModificationHistory',
                Position=0,
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Define the Rule ID you want to view modification history on `n[E] EXAMPLE: 1582038865368")]  # End Parameter
            [Int64]$RuleID,

            [Parameter(
                ParameterSetName='ModificationHistory'
            )]  # End Parameter
            [Switch][Bool]$ModificationHistory

        )  # End param

    $Obj = @()

    Switch ($PSBoundParameters.Keys)
    {

        'Active' {

            $Uri = 'https://' + $Server + ':' + $Port + '/rest/customRules/decisionFeature/live'

            Write-Verbose "Sending query to $Uri"
            $Response = Invoke-WebRequest -Method GET -ContentType 'application/json' -Uri $Uri -WebSession $CybereasonSession

            $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty rules | `
            ForEach-Object {
                $id = ($_.id | Out-String).Trim()
                $Name = ($_.name | Out-String).Trim()
                $RootCause = ($_.rootCause | Out-String).Trim()
                $malopDetectionType = ($_.malopDetectionType | Out-String).Trim()
                $parentId = ($_.rule.parentId | Out-String).Trim()
                $elementType = ($_.rule.root.elementType | Out-String).Trim()
                $facetName = ($_.rule.root.filters.facetName | Out-String).Trim()
                $values = ($_.rule.root.filters.values | Out-String).Trim()
                $filterType = ($_.rule.root.filters.filterType | Out-String).Trim()
                $featureTranslation = ($_.rule.root.filters.featureTranslation | Out-String).Trim()
                $children = $_.rule.root.children
                $malopActivityType = ($_.root.malopActivityType | Out-String).Trim()
                $description = ($_.description | Out-String).Trim()
                $enabled = ($_.enabled | Out-String).Trim()
                $userName = ($_.userName | Out-String).Trim()
                $creationTime = Get-Date -Date ($_.creationTime)
                $updateTime = Get-Date -Date ($_.updateTime)
                $lastTriggerTime = Get-Date -Date ($_.lastTriggerTime)
                $autoRemediationActions = $_.autoRemediationActions
                $autoRemediationStatus = $_.autoRemediationStatus
                $limitExceed = ($Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty limitExceed | Out-String).Trim()

                $Obj += New-Object -TypeName PSObject -Property @{
                    id=$id;
                    Name=$name;
                    RootCause=$RootCause;
                    malopDetectionType=$malopDetectionType;
                    parentId=$parentId;
                    elementType=$elementType;
                    facetName=$facetName;
                    values=$values;
                    filterType=$filterType;
                    featureTranslation=$featureTranslation;
                    children=$children;
                    malopActivityType=$malopActivityType;
                    description=$description;
                    enabled=$enabled;
                    userName=$userName;
                    creationTime=$creationTime;
                    updateTime=$updateTime;
                    lastTriggerTime=$lastTriggerTime;
                    autoRemediationActions=$autoRemediationActions;
                    autoRemediationStatus=$autoRemediationStatus;
                    limitExceed=$limitExceed
                }  # End Properties

            }  # End ForEach-Object

            If ($Obj.Count -eq 0)
            {

                Write-Output "[*] No results were found"

            }  # End If
            Else
            {

                $Obj

            }  # End Else


        }  # End Switch Active

        'Disabled' {

            $Uri = 'https://' + $Server + ':' + $Port + '/rest/customRules/decisionFeature/deleted'

            Write-Verbose "Sending query to $Uri"
            $Response = Invoke-WebRequest -Method GET -ContentType 'application/json' -Uri $Uri -WebSession $CybereasonSession

            $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty rules | `
            ForEach-Object {
                $id = ($_.id | Out-String).Trim()
                $Name = ($_.name | Out-String).Trim()
                $RootCause = ($_.rootCause | Out-String).Trim()
                $malopDetectionType = ($_.malopDetectionType | Out-String).Trim()
                $parentId = ($_.rule.parentId | Out-String).Trim()
                $elementType = ($_.rule.root.elementType | Out-String).Trim()
                $facetName = ($_.rule.root.filters.facetName | Out-String).Trim()
                $values = ($_.rule.root.filters.values | Out-String).Trim()
                $filterType = ($_.rule.root.filters.filterType | Out-String).Trim()
                $featureTranslation = ($_.rule.root.filters.featureTranslation | Out-String).Trim()
                $children = $_.rule.root.children
                $malopActivityType = ($_.root.malopActivityType | Out-String).Trim()
                $description = ($_.description | Out-String).Trim()
                $enabled = ($_.enabled | Out-String).Trim()
                $userName = ($_.userName | Out-String).Trim()
                $creationTime = Get-Date -Date ($_.creationTime)
                $updateTime = Get-Date -Date ($_.updateTime)
                $lastTriggerTime = Get-Date -Date ($_.lastTriggerTime)
                $autoRemediationActions = $_.autoRemediationActions
                $autoRemediationStatus = $_.autoRemediationStatus
                $limitExceed = ($Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty limitExceed | Out-String).Trim()

                $Obj += New-Object -TypeName PSObject -Property @{
                    id=$id;
                    Name=$name;
                    RootCause=$RootCause;
                    malopDetectionType=$malopDetectionType;
                    parentId=$parentId;
                    elementType=$elementType;
                    facetName=$facetName;
                    values=$values;
                    filterType=$filterType;
                    featureTranslation=$featureTranslation;
                    children=$children;
                    malopActivityType=$malopActivityType;
                    description=$description;
                    enabled=$enabled;
                    userName=$userName;
                    creationTime=$creationTime;
                    updateTime=$updateTime;
                    lastTriggerTime=$lastTriggerTime;
                    autoRemediationActions=$autoRemediationActions;
                    autoRemediationStatus=$autoRemediationStatus;
                    limitExceed=$limitExceed
                }  # End Properties

            }  # End ForEach-Object

            If ($Obj.Count -eq 0)
            {

                Write-Output "[*] No results were found"

            }  # End If
            Else
            {

                $Obj

            }  # End Else

        }  # End Switch Disabled

        'RootCauses' {

            $Uri = 'https://' + $Server + ':' + $Port + '/rest/customRules/rootCauses'

            Write-Verbose "Sending query to $Uri"
            $Response = Invoke-WebRequest -Method GET -ContentType 'application/json' -Uri $Uri -WebSession $CybereasonSession

            $Response.Content | ConvertFrom-Json

        }  # End Switch RootCauses

        'DetectionTypes' {

            $Uri = 'https://' + $Server + ':' + $Port + '/rest/customRules/getMalopDetectionTypes'

            Write-Verbose "Sending query to $Uri"
            $Response = Invoke-WebRequest -Method GET -ContentType 'application/json' -Uri $Uri -WebSession $CybereasonSession

            $Response.Content | ConvertFrom-Json

        }  # End Switch DetectionTypes

        'ActivityTypes' {

            $Uri = 'https://' + $Server + ':' + $Port + '/rest/customRules/getMalopActivityTypes'

            Write-Verbose "Sending query to $Uri"
            $Response = Invoke-WebRequest -Method GET -ContentType 'application/json' -Uri $Uri -WebSession $CybereasonSession

            $Response.Content | ConvertFrom-Json

        }  # End Switch ActivityTypes

        'ModificationHistory' {

            $Obj = @()
            $Uri = 'https://' + $Server + ':' + $Port + '/rest/customRules/history/' + $RuleID.ToString()

            Write-Verbose "Sending query to $Uri"
            $Response = Invoke-WebRequest -Method GET -ContentType 'application/json' -Uri $Uri -WebSession $CybereasonSession

            $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty history | `
            ForEach-Object {
                $Username = ($_.username | Out-String).Trim()
                $Date = Get-Date -Date $_.date
                $JsonRef = ($_.changes.jsonRef | Out-String).Trim()
                $OriginalValue = ($_.changes.originalValue | Out-String).Trim()
                $NewValue = ($_.changes.newValue | Out-String).Trim()

                $Obj += New-Object -TypeName PSObject -Property @{Username=$Username; $Date=$Date; JsonRef=$JsonRef; OriginalValue=$OriginalValue; NewValue=$NewValue}

            }  # End ForEach-Object

            If ($Obj.Length -eq 0)
            {

                Write-Output "[*] No results were found"

            }  # End If
            Else
            {

                $Obj

            }  # End Else

        }  # End Switch ModificationHistory

    }  # End Switch

}  # End Function Get-CybereasonCustomDetectionRule


<#
.SYNOPSIS
This cmdlet is used to creates a custom detection rule


.DESCRIPTION
Creates a custom detection rule. Custom detection rules created via API should be created only after adequate research regarding precision and coverage has been completed. Creating a custom detection rule that is not specific enough can have detrimental impact on retention and overall performance of the environment.


.PARAMETER Name
This parameter gives the rule you are creating a name

.PARAMETER FacetName
The name of the Feature on which to filter the base Element

.PARAMETER ChildFacetName
The name of the child feature on which to filter the base Child Element

.PARAMETER RootCause
The Element which is identified as the root cause in the Malop generated from the custom detection rule. Possible values include: self (the base Element is malicious) OR imageFile (the image file for the base Element is malicious) OR parentProcess (the parent process for the base Element is malicious)

.PARAMETER MalopDetectionType
The detection type to assign to Malops generated from this custom detection rule.

.PARAMETER MalopActivityType
The activity type to assign to Malops generated from this custom detection rule.

.PARAMETER ElementType
The Element used as the base of the custom detection rule.

.PARAMETER ChildElementType
The Child Element used as the base of the custom detection rule.

.PARAMETER ConnectionFeature
Parameter to define the link between parent and child facets. https://nest.cybereason.com/api-documentation/all-versions/APIReference/CustomRulesAPI/customRulesConnectionFeatures.html#supported-features-for-linking-elements-in-a-custom-detection-rule

.PARAMETER Description
The description for this custom detection rule.

.PARAMETER EnableOnCreation
Indicates whether or not to enable this detection rule upon creation. Defining this switch parameter sets this value to true to automatically enable the rule.

.PARAMETER KillProcess
This parameter indicates you want to kill any malicious discovered processes

.PARAMETER QuarantineFile
This paraemeter defines that you want to quarantine files that are infectious

.PARAMETER IsolateMachine
This parameter indicates you want to isolate machines that become infected


.EXAMPLE
New-CybereasonCustomDetectionRule
# This example


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None


.LINK
https://nest.cybereason.com/documentation/api-documentation/all-versions/add-custom-detection-rules
https://roberthsoborne.com
https://writeups.osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
Function New-CybereasonCustomDetectionRule {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] This parameter is a name to assign to the custom rule. `n[E] EXAMPLE: Test Rule 1"
            )]  # End Parameter
            [String]$Name,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] The name of the Feature on which to filter the base Element.`n[E] EXAMPLE: maliciousUseOfRegsvr32ModuleEvidence")]  # End Parameter
            [String]$FacetName,

            [Parameter(
                ParameterSetName='Children',
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] The name of the child Feature on which to filter the base Element.`n[E] EXAMPLE: maliciousUseOfRegsvr32ModuleEvidence")]  # End Parameter
            [String]$ChildFacetName,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] The Element which is identified as the root cause in the Malop generated from the custom detection rule. `n[E] EXAMPLE: parentProcess")]  # End Parameter
            [ValidateSet('self','imageFile','parentProcess')]
            [String]$RootCause,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] The detection type to assign to Malops generated from this custom detection rule.`n[E] EXAMPLE: BLACKLIST")]  # End Parameter
            [ValidateSet('BLACKLIST','CNC','CUSTOM_RULE','UNAUTHORIZED_USER','CREDENTIAL_THEFT','DATA_TRANSMISSION_VOLUME','ELEVATED_ACCESS','EXTENSION_MANIPULATION','KNOWN_MALWARE','LATERAL_MOVEMENT','MALWARE_PROCESS','MALICIOUS_PROCESS','PUP','PERSISTENCE','PHISHING','PROCESS_INJECTION','RANSOMWARE','RECONNAISSANCE')]
            [String]$MalopDetectionType,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] The activity type to assign to Malops generated from this custom detection rule.`n[E] EXAMPLE: STOLEN_CREDENTIALS")]  # End Parameter
            [ValidateSet('CNC_COMMUNICATION','DATA_THEFT','MALICIOUS_INFECTION','LATERAL_MOVEMENT','PRIVILEGE_ESCALATION','RANSOMWARE','SCANNING','STOLEN_CREDENTIALS')]
            [String]$MalopActivityType,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] The Element used as the base of the custom detection rule. Possible values include: Process or LogonSession `n[E] EXAMPLE: Process")]  # End Parameter
            [ValidateSet('Process','LogonSession')]
            [String]$ElementType,

            [Parameter(
                ParameterSetName='Children',
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] The Element used as the base of the custom detection rule. Possible values include: Process or LogonSession `n[E] EXAMPLE: Process")]  # End Parameter
            [ValidateSet('Process','LogonSession')]
            [String]$ChildElementType,

            [Parameter(
                ParameterSetName='Children',
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] The name of the Feature that connects the linked Elements. `n[E] EXAMPLE: msword.exe")]  # End Parameter
            [String]$ChildElementName,

            [Parameter(
                ParameterSetName='Children',
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="The name of the Feature that connects the linked Elements. This Feature name corresponds with the name of the linked Element. For details on the Features available to use as connection features, see Supported Features for Linking Elements in a Custom Detection Rule. https://nest.cybereason.com/api-documentation/all-versions/APIReference/CustomRulesAPI/customRulesConnectionFeatures.html#supported-features-for-linking-elements-in-a-custom-detection-rule")]  # End Parameter
            [ValidateSet('DomainName','Machine','urlDomains','fileHash','ownerMachine','remoteMachine','user','file','autorun','children','connections','hostedChildren','hostProcess','imageFile','injectedChildren','loadedModules','originInjector','parentProcess','scheduledTask','service','executableActions','binaryFile')]
            [String]$ConnectionFeature,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [String]$Description = $Name,

            [Parameter(
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$EnableOnCreation,

            [Parameter(
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$KillProcess,

            [Parameter(
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$QuarantineFile,

            [Parameter(
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$IsolateMachine
        )  # End param

    If ($EnableOnCreation.IsPresent) { $EnableOnCreate = 'true' }  # End If
    Else { $EnableOnCreate = 'false' }  # End Else

    If ($QuarantineFile.IsPresent) { $EnableQuarantine = 'true' }  # End If
    Else { $EnableQuarantine = 'false' }  # End Else

    If ($IsolateMachine.IsPresent) { $EnableIsolate = 'true' }  # End If
    Else { $EnableIsolate = 'false' }  # End Else

    If ($KillProcess.IsPresent) { $EnableKill = 'true' }  # End If
    Else { $EnableKill = 'false' }  # End Else


    $Uri = 'https://' + $Server + ':' + $Port + '/rest/customRules/decisionFeature/create'

    Switch ($PSBoundParameters.Keys)
    {

        'Children' {

            $JsonData = '{"name":"' + $Name + '","rootCause":"' + $RootCause + '","malopDetectionType":"' + $MalopDetectionType + '","autoRemediationActions":{"killProcess":' + $EnableKill + ',"quarantineFile":' + $EnableQuarantine + ',"isolateMachine":' + $EnableIsolate + '},"autoRemediationStatus":"Active","rule":{"root":{"elementType":"' + $ElementType + '","elementTypeTranslation":"' + $ElementType + '","filters":[{"facetName":"' + $FacetName + '","filterType":"Equals","values":[True]}],"children": [{"elementType":"' + $ChildElementType + '","elementTypeTranslation":"' + $ChildElementType + '","connectionFeature":"' + $ConnectionFeature + '","connectionFeatureTranslation":"' + $ConnectionFeature + '","reversed":False,"filters": [{"facetName":"' + $ChildFacetName + '","filterType":"ContainsIgnoreCase","values":["' + $ChildElementName + '"]}]}]},"malopActivityType":"' + $MalopActivityType +  '"},"description":"' + $Description + '","enabled":' + $EnableOnCreate + '}'

        }  # End Switch Children

        Default {

            $JsonData = '{"name":"' + $Name + '","rootCause":"' + $RootCause + '","malopDetectionType":"' + $MalopDetectionType + '","autoRemediationActions":{"killProcess":' + $EnableKill + ',"quarantineFile":' + $EnableQuarantine + ',"isolateMachine":' + $EnableIsolate + '},"autoRemediationStatus":"Active","rule":{"root":{"elementType":"' + $ElementType + '","elementTypeTranslation":"' + $ElementType + '","filters":[{"facetName":"' + $FacetName + '","filterType":"Equals","values":[True]}]}},"malopActivityType":"' + $MalopActivityType +  '"},"description":"' + $Description + '","enabled":' + $EnableOnCreate + '}'

        }  # End Switch Default

    }  # End Switch

    Write-Verbose "Sending query to $Uri"
    $Response = Invoke-WebRequest -Method POST -ContentType 'application/json' -Uri $Uri -WebSession $CybereasonSession -Body $JsonData

    $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty rules | `
            ForEach-Object {
                $id = ($_.id | Out-String).Trim()
                $Name = ($_.name | Out-String).Trim()
                $RootCause = ($_.rootCause | Out-String).Trim()
                $malopDetectionType = ($_.malopDetectionType | Out-String).Trim()
                $parentId = ($_.rule.parentId | Out-String).Trim()
                $elementType = ($_.rule.root.elementType | Out-String).Trim()
                $facetName = ($_.rule.root.filters.facetName | Out-String).Trim()
                $values = ($_.rule.root.filters.values | Out-String).Trim()
                $filterType = ($_.rule.root.filters.filterType | Out-String).Trim()
                $featureTranslation = ($_.rule.root.filters.featureTranslation | Out-String).Trim()
                $children = $_.rule.root.children
                $malopActivityType = ($_.root.malopActivityType | Out-String).Trim()
                $description = ($_.description | Out-String).Trim()
                $enabled = ($_.enabled | Out-String).Trim()
                $userName = ($_.userName | Out-String).Trim()
                $creationTime = Get-Date -Date ($_.creationTime)
                $updateTime = Get-Date -Date ($_.updateTime)
                $lastTriggerTime = Get-Date -Date ($_.lastTriggerTime)
                $autoRemediationActions = $_.autoRemediationActions
                $autoRemediationStatus = $_.autoRemediationStatus
                $limitExceed = ($Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty limitExceed | Out-String).Trim()

                $Obj += New-Object -TypeName PSObject -Property @{id=$id; Name=$name; RootCause=$RootCause; malopDetectionType=$malopDetectionType; parentId=$parentId; elementType=$elementType; facetName=$facetName; Values=$values;filterType=$filterType;featureTranslation=$featureTranslation;children=$children;malopActivityType=$malopActivityType;description=$description;enabled=$enabled;userName=$userName;creationTime=$creationTime;updateTime=$updateTime;lastTriggerTime=$lastTriggerTime;autoRemediationActions=$autoRemediationActions;autoRemediationStatus=$autoRemediationStatus;limitExceed=$limitExceed}  # End Properties

            }  # End ForEach-Object

            $Obj

}  # End Function New-CybereasonCustomDetectionRule


<#
.SYNOPSIS
This cmdlet is used to updates an existing custom detection rule


.DESCRIPTION
Updates an existing custom detection rule. Custom Detection Rules can be created via API but should be created only once adequate research regarding precision and coverage has been completed. Creating a custom detection rule that is not specific enough can have detrimental impact on Retention and overall performance of the environment


.PARAMETER RuleID
The unique identifier for the custom detection rule.

.PARAMETER Name
This parameter gives the rule you are creating a name

.PARAMETER FacetName
The name of the Feature on which to filter the base Element

.PARAMETER ChildFacetName
The name of the child feature on which to filter the base Child Element

.PARAMETER RootCause
The Element which is identified as the root cause in the Malop generated from the custom detection rule. Possible values include: self (the base Element is malicious) OR imageFile (the image file for the base Element is malicious) OR parentProcess (the parent process for the base Element is malicious)

.PARAMETER MalopDetectionType
The detection type to assign to Malops generated from this custom detection rule.

.PARAMETER MalopActivityType
The activity type to assign to Malops generated from this custom detection rule.

.PARAMETER ElementType
The Element used as the base of the custom detection rule.

.PARAMETER ChildElementType
The Child Element used as the base of the custom detection rule.

.PARAMETER ConnectionFeature
Parameter to define the link between parent and child facets. https://nest.cybereason.com/api-documentation/all-versions/APIReference/CustomRulesAPI/customRulesConnectionFeatures.html#supported-features-for-linking-elements-in-a-custom-detection-rule

.PARAMETER Description
The description for this custom detection rule.

.PARAMETER EnableOnCreation
Indicates whether or not to enable this detection rule upon creation. Defining this switch parameter sets this value to true to automatically enable the rule.

.PARAMETER KillProcess
This parameter indicates you want to kill any malicious discovered processes

.PARAMETER QuarantineFile
This paraemeter defines that you want to quarantine files that are infectious

.PARAMETER IsolateMachine
This parameter indicates you want to isolate machines that become infected

.PARAMETER Username
The Cybereason user name for the user updating the rule


.EXAMPLE
Set-CybereasonCustomDetectionRule -RuleID 1580246401162 -Name 'Test Rule 1' -FacetName 'maliciousUseOfRegsvr32ModuleEvidence' -ChildFacetName name  -RootCause self


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None


.LINK
https://nest.cybereason.com/documentation/api-documentation/all-versions/update-custom-detection-rule
https://roberthsoborne.com
https://writeups.osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
Function Set-CybereasonCustomDetectionRule {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] The unique identifier for the custom detection rule.`n[E] EXAMPLE: 1580246401162")]  # End Parameter
            [Int64]$RuleID,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] This parameter is a name to assign to the custom rule. `n[E] EXAMPLE: Test Rule 1"
            )]  # End Parameter
            [String]$Name,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] The name of the Feature on which to filter the base Element.`n[E] EXAMPLE: maliciousUseOfRegsvr32ModuleEvidence")]  # End Parameter
            [String]$FacetName,

            [Parameter(
                ParameterSetName='Children',
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] The name of the child Feature on which to filter the base Element.`n[E] EXAMPLE: name")]  # End Parameter
            [String]$ChildFacetName,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] The Element which is identified as the root cause in the Malop generated from the custom detection rule. `n[E] EXAMPLE: parentProcess")]  # End Parameter
            [ValidateSet('self','imageFile','parentProcess')]
            [String]$RootCause,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] The detection type to assign to Malops generated from this custom detection rule.`n[E] EXAMPLE: BLACKLIST")]  # End Parameter
            [ValidateSet('BLACKLIST','CNC','CUSTOM_RULE','UNAUTHORIZED_USER','CREDENTIAL_THEFT','DATA_TRANSMISSION_VOLUME','ELEVATED_ACCESS','EXTENSION_MANIPULATION','KNOWN_MALWARE','LATERAL_MOVEMENT','MALWARE_PROCESS','MALICIOUS_PROCESS','PUP','PERSISTENCE','PHISHING','PROCESS_INJECTION','RANSOMWARE','RECONNAISSANCE')]
            [String]$MalopDetectionType,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] The activity type to assign to Malops generated from this custom detection rule.`n[E] EXAMPLE: STOLEN_CREDENTIALS")]  # End Parameter
            [ValidateSet('CNC_COMMUNICATION','DATA_THEFT','MALICIOUS_INFECTION','LATERAL_MOVEMENT','PRIVILEGE_ESCALATION','RANSOMWARE','SCANNING','STOLEN_CREDENTIALS')]
            [String]$MalopActivityType,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] The Element used as the base of the custom detection rule. Possible values include: Process or LogonSession `n[E] EXAMPLE: Process")]  # End Parameter
            [ValidateSet('Process','LogonSession')]
            [String]$ElementType,

            [Parameter(
                ParameterSetName='Children',
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] The Element used as the base of the custom detection rule. Possible values include: Process or LogonSession `n[E] EXAMPLE: Process")]  # End Parameter
            [ValidateSet('Process','LogonSession')]
            [String]$ChildElementType,

            [Parameter(
                ParameterSetName='Children',
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] The name of the Feature that connects the linked Elements. `n[E] EXAMPLE: msword.exe")]  # End Parameter
            [String]$ChildElementName,

            [Parameter(
                ParameterSetName='Children',
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="The name of the Feature that connects the linked Elements. This Feature name corresponds with the name of the linked Element. For details on the Features available to use as connection features, see Supported Features for Linking Elements in a Custom Detection Rule. https://nest.cybereason.com/api-documentation/all-versions/APIReference/CustomRulesAPI/customRulesConnectionFeatures.html#supported-features-for-linking-elements-in-a-custom-detection-rule")]  # End Parameter
            [ValidateSet('DomainName','Machine','urlDomains','fileHash','ownerMachine','remoteMachine','user','file','autorun','children','connections','hostedChildren','hostProcess','imageFile','injectedChildren','loadedModules','originInjector','parentProcess','scheduledTask','service','executableActions','binaryFile')]
            [String]$ConnectionFeature,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [String]$Description = $Name,

            [Parameter(
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$EnableOnCreation,

            [Parameter(
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$KillProcess,

            [Parameter(
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$QuarantineFile,

            [Parameter(
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$IsolateMachine,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] The Cybereason user name for the user updating the rule.`n[E] EXAMPLE: admin@cybereason.com")]  # End Parameter
            [String]$Username

        )  # End param

    If ($EnableOnCreation.IsPresent) { $EnableOnCreate = 'true' }  # End If
    Else { $EnableOnCreate = 'false' }  # End Else

    If ($QuarantineFile.IsPresent) { $EnableQuarantine = 'true' }  # End If
    Else { $EnableQuarantine = 'false' }  # End Else

    If ($IsolateMachine.IsPresent) { $EnableIsolate = 'true' }  # End If
    Else { $EnableIsolate = 'false' }  # End Else

    If ($KillProcess.IsPresent) { $EnableKill = 'true' }  # End If
    Else { $EnableKill = 'false' }  # End Else

    $Uri = 'https://' + $Server + ':' + $Port + '/rest/customRules/decisionFeature/update'

    $JsonData = '{"id":' + $RuleID + ',"name":"' + $Name + '","rootCause":"' + $RootCause + '","malopDetectionType":"' + $MalopDetectionType + '","autoRemediationActions":{"killProcess":' + $EnableKill + ',"quarantineFile":' + $EnableQuarantine + ',"isolateMachine":' + $EnableIsolate + '},"autoRemediationStatus":"Active","rule":{"root":{"elementType":"' + $ElementType + '","elementTypeTranslation":"' + $ElementType + '","filters":[{"facetName":"' + $FacetName + '","filterType":"Equals","values":[True]}],"children": [{"elementType":"' + $ChildElementType + '","elementTypeTranslation":"' + $ChildElementName + '","connectionFeature":"' + $ConnectionFeature + '","connectionFeatureTranslation":"' + $ConnectionFeature + '","reversed":False,"filters": [{"facetName":"' + $ChildElementType + '","filterType":"ContainsIgnoreCase","values":["' + $ChildElementName + '"]}]}]},"malopActivityType":"' + $MalopActivityType + '"},"description":"' + $Description + '","enabled":' + $EnableOnCreate + '})'

    Write-Verbose "Sending query to $Uri"
    $Response = Invoke-WebRequest -Method POST -ContentType 'application/json' -Uri $Uri -WebSession $CybereasonSession -Body $JsonData

    $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty rules | `
            ForEach-Object {
                $id = ($_.id | Out-String).Trim()
                $Name = ($_.name | Out-String).Trim()
                $RootCause = ($_.rootCause | Out-String).Trim()
                $malopDetectionTypes = ($_.malopDetectionType | Out-String).Trim()
                $parentId = ($_.rule.parentId | Out-String).Trim()
                $elementType = ($_.rule.root.elementType | Out-String).Trim()
                $facetName = ($_.rule.root.filters.facetName | Out-String).Trim()
                $values = ($_.rule.root.filters.values | Out-String).Trim()
                $filterType = ($_.rule.root.filters.filterType | Out-String).Trim()
                $featureTranslation = ($_.rule.root.filters.featureTranslation | Out-String).Trim()
                $children = $_.rule.root.children
                $malopActivityType = ($_.root.malopActivityType | Out-String).Trim()
                $description = ($_.description | Out-String).Trim()
                $enabled = ($_.enabled | Out-String).Trim()
                $userName = ($_.userName | Out-String).Trim()
                $creationTime = Get-Date -Date ($_.creationTime)
                $updateTime = Get-Date -Date ($_.updateTime)
                $lastTriggerTime = Get-Date -Date ($_.lastTriggerTime)
                $autoRemediationActions = $_.autoRemediationActions
                $autoRemediationStatus = $_.autoRemediationStatus
                $limitExceed = ($Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty limitExceed | Out-String).Trim()

                $Obj += New-Object -TypeName PSObject -Property @{id=$id; Name=$name; RootCause=$RootCause; malopDetectionType=$MalopDetectionTypes; parentId=$parentId; elementType=$elementType; facetName=$facetName; Values=$values;filterType=$filterType;featureTranslation=$featureTranslation;children=$children;malopActivityType=$malopActivityType;description=$description;enabled=$enabled;userName=$userName;creationTime=$creationTime;updateTime=$updateTime;lastTriggerTime=$lastTriggerTime;autoRemediationActions=$autoRemediationActions;autoRemediationStatus=$autoRemediationStatus;limitExceed=$limitExceed}  # End Properties

            }  # End ForEach-Object

            $Obj

}  # End Function Set-CybereasonCustomDetectionRule


<#
.SYNOPSIS
Sends a request to return details on all or a selected group of sensors. You must be assigned the System Admin role to send requests to this endpoint URL.


.PARAMETER Limit
The number of sensors to which to send the request. Valid values run from 0-1000.

.PARAMETER Offset
Set to 0 to receive the first limit set of sensors.

.PARAMETER Sort
The order in which to receive results. Valid values are ASC (ascending) or DESC (descending)

.PARAMETER Filter
An object containing details on the filter to apply to return a select group of sensors. f you add a parameter in the filters object, ensure you use this syntax: {“fieldName”: “<filter parameter>”, “operator”: “<operator>”, “values”: [“<value>”]}
Field 	Type 	Description
actionsInProgress 	Integer 	The number of actions in progress (i.e. Not Resolved) on the machine.
amStatus 	Enum 	

The Anti-Malware installation status for the sensor. Possible values include:

    AM_INSTALLED
    AM_UNINSTALLED

antiExploitStatus 	Enum 	

The status of the Exploit Prevention feature. Possible values include:

    ENABLED
    DISABLED

This field returns a value only if you have enabled Exploit Prevention.

This field is applicable for versions 20.1 and higher.
antiMalwareStatus 	Enum 	

The Anti-Malware prevention mode for the sensor. Possible values include:

    AM_DETECT_DISINFECT
    AM_DEFAULT

archiveTimeMs 	Timestamp 	The time (in epoch) when the sensor was archived.
archiveOrUnarchiveComment 	String 	The comment added when a sensor was archived or unarchived.
collectionComponents 	Enum 	

Any special collections enabled on the server and/or sensor. Possible values include:

    DPI
    Metadata
    File events
    Registry events

collectionStatus 	Enum 	

States whether the machine has data collection enabled. Possible values include:

    ENABLED
    DISABLED
    SUSPENDED

compliance 	Boolean 	Indicates whether the current sensor settings match the policy settings.
cpuUsage 	Float 	The amount of CPU used by the machine (expressed as a percentage).
criticalAsset 	Boolean 	The value assigned for the machine for the CRITICAL ASSET sensor tag.
customTags 	String 	A list of custom sensor tags assigned to the machine.
deliveryTime 	Timestamp 	The time (in epoch) when the last policy update was delivered to the sensor
department 	String 	The value assigned to the machine for the DEPARTMENT sensor tag.
deviceType 	String 	The value assigned to the machine for the DEVICE TYPE sensor tag.
disconnected 	Boolean 	Indicates whether a sensor is currently disconnected.
disconnectionTime 	Timestamp 	Time the machine was disconnected. Returns 0 if this is the first connection time. After the first connection, this is the time it was last connected.
exitReason 	String 	The reason the sensor service (minionhost.exe) stopped.
externalIpAddress 	String 	The machine’s external IP address for the local network.
firstSeenTime 	Timestamp 	The first time the machine was recognized. Timestamp values are returned in epoch.
fullScanStatus 	Enum 	The status set for the sensor for the full scan.
fqdn 	String 	The fully qualified domain name (fqdn) for the machine.
fwStatus 	Enum 	

The status of the Personal Firewall Control feature. Possible values include:

    DISABLED
    ENABLED

This field returns a value only if you have enabled Endpoint Controls.

This field is applicable for versions 19.2 and higher.
guid 	String 	The globally unique sensor identifier.
lastStatusAction 	String 	The last action taken that changed the sensor status.
lastUpgradeResult 	Enum 	

The result of the last upgrade process. Possible values include:

    None
    Pending
    InProgress
    FailedSending
    Primed
    UnknownProbe
    NotSupported
    Disconnected
    TimeoutSending
    Failed
    Succeeded
    Timeout
    InvalidState
    UnauthorizedUser
    partialResponse
    ChunksRequired
    Aborted
    GettingChunks
    ProbeRemoved
    FailedSendingToServer
    Started
    SendingMsi
    MsiSendFail
    MsiFileCorrupted
    AlreadyUpdated
    NewerInstalled

lastUpgradeSteps 	Enum 	

A list of step taken in the upgrade process. Possible values include:

    None
    Pending
    InProgress
    FailedSending
    Primed
    UnknownProbe
    NotSupported
    Disconnected
    TimeoutSending
    Failed
    Succeeded
    Timeout
    InvalidState
    UnauthorizedUser
    partialResponse
    ChunksRequired
    Aborted
    GettingChunks
    ProbeRemoved
    FailedSendingToServer
    Started
    SendingMsi
    MsiSendFail
    MsiFileCorrupted
    AlreadyUpdated
    NewerInstalled

If there is a failure to upgrade the sensor, this list shows the failure.
internalIpAddress 	String 	The machine’s internal IP address as identified by the sensor.
isolated 	Boolean 	States whether the machine is isolated. Returns true if the machine is isolated.
lastFullScheduleScanSuccessTime 	Timestamp 	The time (in epoch) that the sensor last did a successful full scan.
lastQuickScheduleScanSuccessTime 	Timestamp 	The time (in epoch) that the sensor last did a successful quick scan.
lastPylumInfoMsgUpdateTime 	Timestamp 	The last time (in epoch) the sensor sent a message to the Cybereason server.
location 	String 	The value assigned for this machine for the LOCATION sensor tag.
machineName 	String 	The name of the machine.
memoryUsage 	Long 	The amount of RAM on the hosting computer used by the sensor.
offlineTimeMS 	Timestamp 	The last time (in epoch) that the sensor was offline.
onlineTimeMS 	Timestamp 	The last time the sensor was seen online.
organization 	String 	The organization name for the machine on which the sensor is installed.
osType 	Enum 	

The operating system running on the machine. Possible values include:

    UNKNOWN_OS
    WINDOWS
    OSX
    LINUX

osVersionType 	Enum 	

Version of operating system for the machine. Possible values include:

    Windows_8_1
    Windows_8
    Windows_7
    Windows_Vista
    Windows_XP_Professional_x64_Edition
    Windows_XP
    Windows_2000
    Windows_Server_2012_R2
    Windows_Server_2012
    Windows_Server_2008_R2
    Windows_Server_2008
    Windows_Server_2003_R2
    Windows_Home_Server
    Windows_Server_2003
    Windows_Server_2016
    Windows_Server_2019
    Windows_10
    Catalina_10_15
    Mojave_10_14
    High_Sierra_10_13
    Sierra_10_12
    El_Capitan_10_11
    Yosemite_10_10
    Maverick_10_9
    Centos_Linux_6
    Centos_Linux_7
    Red_Hat_Enterprise_Linux_6
    Red_Hat_Enterprise_Linux_7
    Ubuntu_Linux_12
    Ubuntu_Linux_14
    Ubuntu_Linux_16
    Ubuntu_Linux_17
    Ubuntu_Linux_18
    Oracle_Linux_6
    Oracle_Linux_7
    Suse_Linux_12
    Amazon_Linux_2011__09
    Amazon_Linux_2012__03
    Amazon_Linux_2012__09
    Amazon_Linux_2013__03
    Amazon_Linux_2013__09
    Amazon_Linux_2014__03
    Amazon_Linux_2014__09
    Amazon_Linux_2015__03
    Amazon_Linux_2015__09
    Amazon_Linux_2016__03
    Amazon_Linux_2016__09
    Amazon_Linux_2017__03
    Debian_Linux_8
    Debian_Linux_9

outdated 	Boolean 	States whether or not the sensor version is out of sync with the server version.
pendingActions 	Array 	A list of actions pending to run on the sensor.
policyId 	String 	The unique identifier the Cybereason platform uses for the policy assigned to the sensor.
policyName 	String 	The name of the policy assigned to this sensor.
powerShellStatus 	Enum 	

The PowerShell Prevention mode. Possible values include:

    PS_DISABLED
    PS_ENABLED
    PS_DEFAULT

preventionError 	String 	The error received for prevention by the sensor.
preventionStatus 	Enum 	

The Execution Prevention mode. Possible values include:

    ENABLE
    DISABLE
    UNINSTALL
    UNKNOWN

proxyAddress 	String 	The address for the Proxy server used by this sensor.
pylumID 	String 	The unique identifier assigned by Cybereason to the sensor.
quickScanStatus 	Enum 	The status set for the sensor for a quick scan.
ransomwareStatus 	Enum 	

The Anti-Ransomware mode. Possible values include:

    UNKNOWN
    DISABLED
    DETECT_ONLY
    DETECT_AND_SUSPEND
    DETECT_SUSPEND_PREVENT

remoteShellStatus 	Enum 	

Whether or not the Remote Shell utility is enabled for the sensor. Possible values include:

    AC_DISABLED
    AC_ENABLED

This field returns a value only if you have enabled Remote Shell for your Cybereason server.
sensorId 	String 	The unique identifier for a sensor.
sensorArchivedByUser 	String 	The Cybereason user name for the user who archived the selected sensor.
sensorLastUpdate 	Timestamp 	The last time (in epoch) that the sensor was updated.
serverId 	String 	The unique identifier for the sensor’s server.
serverName 	String 	The name of the server for the sensor.
serviceStatus 	Enum 	

Indicates the current value of the Anti-Malware service. Possible values include:

    DISABLED
    DETECT
    PREVENT
    SET_BY_POLICY

siteName 	String 	The name of the site for the sensor.
siteId 	Long 	The identifier for the sensor’s site.
staleTimeMS 	Integer 	The time (in epoch) when the Sensor was classified as Stale.
staticAnalysisDetectMode 	Enum 	

The value for the Artificial Intelligence Detect mode in the Anti-Malware settings. Possible values include:

    DISABLED
    CAUTIOUS
    MODERATE
    AGGRESSIVE
    SET_BY_POLICY

staticAnalysisDetectModeOrigin 	Enum 	

The source of the value for the Artificial Intelligence Detect mode setting. Possible values include:

    NOT_AVAILBLE
    SET_BY_POLICY
    SET_MANUALLY
    AWAITING_UPDATE

staticAnalysisPreventMode 	Enum 	

The value for the Artificial Intelligence Prevent Mode in the Anti-Malware settings. Possible values include:

    DISABLED
    CAUTIOUS
    MODERATE
    AGGRESSIVE

staticAnalysisPreventModeOrigin 	Enum 	

The source of the value for the Artificial Intelligence Prevent mode setting. Possible values include:

    NOT_AVAILBLE
    SET_BY_POLICY
    SET_MANUALLY
    AWAITING_UPDATE

status 	Enum 	

The status of the sensor. Possible values include:

    Online
    Offline
    Stale
    Archived

statusTimeMS 	Timestamp 	The last time (in epoch) when the sensor sent a status.
upTime 	Long 	The time the sensors have been in the UP state.
usbStatus 	Enum 	

The status of the Device Control feature. Possible values include:

    ENABLED: the Cybereason platform blocks access to all USB devices
    DISABLED: the Cybereason platform allows access to all USB devices

This field returns a value only if you have enabled Endpoint Controls.

This field is applicable for versions 19.2 and higher.
version 	String 	The sensor version number.

.EXAMPLE
Set-CybereasonCustomDetectionRule -RuleID 1580246401162 -Name 'Test Rule 1' -FacetName 'maliciousUseOfRegsvr32ModuleEvidence' -ChildFacetName name  -RootCause self


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None

.LINK
https://nest.cybereason.com/documentation/api-documentation/all-versions/query-sensors#getsensors
https://roberthsoborne.com
https://writeups.osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
Function Get-CybereasonListAllSensors {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Define the number of sensors to which to send the request (1-1000).`n[E] EXAMPLE: 100")]  # End Parameter
            [Int32]$Limit,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [ValidateRange(0,1000)]
            [Int32]$Offset = 0,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Define the sort order as Ascending or Descending.`n[E] EXAMPLE: ASC")]  # End Parameter
            [ValidateSet("ASC","DESC")]
            [String]$Sort = "DESC",

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Define a field name to filter by. Use a : to separate the value. Use the command 'Get-Help Get-CybereasonListAllSensors -Parameter Filter' to view the possible Value options for each field name`n[E] EXAMPLE: 'machineName:server01', 'usbStatus:Enum'")]  # End Parameter
            [ValidateSet("actionsInProgress:<int>","amStatus:AM_INSTALLED","amStatus:AM_UNINSTALLED","antiExploitStatus:ENABLED","antiExploitStatus:DISABLED","antiMalwareStatus:AM_DETECT_DISINFECT","antiMalwareStatus:AM_DEFAULT","archiveTimeMs:<timestamp>","archiveOrUnarchiveComment:<string>","collectionComponents:DPI","collectionComponents:Metadata","collectionComponents:File events","collectionComponents:Registry events","collectionStatus:ENABLED","collectionStatus:DISABLED","collectionStatus:SUSPENDED","compliance:true","compliance:false","cpuUsage:<float>","criticalAsset:true","criticalAsset:false","customTags:<string>","deliveryTime:<timestamp>","department:<string DEPARTMENT sensor tag>","deviceType:<string DEVICE TYPE sensor tag>","disconnected:true","disconnected:false","disconnectionTime:<timestamp>","exitReason:<string reason the sensor stopped>","externalIpAddress:<string ipaddress>","firstSeenTime:<timestamp>","fullScanStatus","fqdn:<string FQDN of machine>","fwStatus:DISABLED","fwStatus:ENABLED","guid:<string>","lastStatusAction:<string>","lastUpgradeResult:None","lastUpgradeResult:Pending","lastUpgradeResult:InProgress","lastUpgradeResult:FailedSending","lastUpgradeResult:Primed","lastUpgradeResult:UnknownProbe","lastUpgradeResult:NotSupported","lastUpgradeResult:Disconnected","lastUpgradeResult:TimeoutSending","lastUpgradeResult:Failed","lastUpgradeResult:Succeeded","lastUpgradeResult:Timeout","lastUpgradeResult:InvalidState","lastUpgradeResult:UnauthorizedUser","lastUpgradeResult:partialResponse","lastUpgradeResult:ChunksRequired","lastUpgradeResult:Aborted","lastUpgradeResult:GettingChunks","lastUpgradeResult:ProbeRemoved","lastUpgradeResult:FailedSendingToServer","lastUpgradeResult:Started","lastUpgradeResult:SendingMsi","lastUpgradeResult:MsiSendFail","lastUpgradeResult:MsiFileCorrupted","lastUpgradeResult:AlreadyUpdated","lastUpgradeResult:NewerInstalled","lastUpgradeSteps:None","lastUpgradeSteps:Pending","lastUpgradeSteps:InProgress","lastUpgradeSteps:FailedSending","lastUpgradeSteps:Primed","lastUpgradeSteps:UnknownProbe","lastUpgradeSteps:NotSupported","lastUpgradeSteps:Disconnected","lastUpgradeSteps:TimeoutSending","lastUpgradeSteps:Failed","lastUpgradeSteps:Succeeded","lastUpgradeSteps:Timeout","lastUpgradeSteps:InvalidState","lastUpgradeSteps:UnauthorizedUser","lastUpgradeSteps:partialResponse","lastUpgradeSteps:ChunksRequired","lastUpgradeSteps:Aborted","lastUpgradeSteps:GettingChunks","lastUpgradeSteps:ProbeRemoved","lastUpgradeSteps:FailedSendingToServer","lastUpgradeSteps:Started","lastUpgradeSteps:SendingMsi","lastUpgradeSteps:MsiSendFail","lastUpgradeSteps:MsiFileCorrupted","lastUpgradeSteps:AlreadyUpdated","lastUpgradeSteps:NewerInstalled,","internalIpAddress:<ipaddress>","isolated:true","isolated:false","lastFullScheduleScanSuccessTime:<timestamp>","lastQuickScheduleScanSuccessTime:<timestamp>","lastPylumInfoMsgUpdateTime:<timestamp>","location:<string value of LOCATION sensor tag>","machineName:<string>","memoryUsage:<Long>","offlineTimeMS:<timestamp>","onlineTimeMS:<timestamp>","organization:<string>","osType:UNKNOWN_OS","osType:WINDOWS","osType:OSX","osType:LINUX","osVersionType:Windows_10","osVersionType:Windows_8_1","osVersionType:Windows_8","osVersionType:Windows_7","osVersionType:Windows_Vista","osVersionType:Windows_XP_Professional_x64_Edition","osVersionType:Windows_XP","osVersionType:Windows_2000","osVersionType:Windows_Server_2012_R2","osVersionType:Windows_Server_2012","osVersionType:Windows_Server_2008_R2","osVersionType:Windows_Server_2008","osVersionType:Windows_Server_2003_R2","osVersionType:Windows_Home_Server","osVersionType:Windows_Server_2003","osVersionType:Windows_Server_2016","osVersionType:Windows_Server_2019","osVersionType:Catalina_10_15","osVersionType:Mojave_10_14","osVersionType:High_Sierra_10_13","osVersionType:Sierra_10_12","osVersionType:El_Capitan_10_11","osVersionType:Yosemite_10_10","osVersionType:Maverick_10_9","osVersionType:Centos_Linux_6","osVersionType:Centos_Linux_7","osVersionType:Red_Hat_Enterprise_Linux_6","osVersionType:Red_Hat_Enterprise_Linux_7","osVersionType:Ubuntu_Linux_12","osVersionType:Ubuntu_Linux_14","osVersionType:Ubuntu_Linux_16","osVersionType:Ubuntu_Linux_17","osVersionType:Ubuntu_Linux_18","osVersionType:Oracle_Linux_6","osVersionType:Oracle_Linux_7","osVersionType:Suse_Linux_12","osVersionType:Amazon_Linux_2011__09","osVersionType:Amazon_Linux_2012__03","osVersionType:Amazon_Linux_2012__09","osVersionType:Amazon_Linux_2013__03","osVersionType:Amazon_Linux_2013__09","osVersionType:Amazon_Linux_2014__03","osVersionType:Amazon_Linux_2014__09","osVersionType:Amazon_Linux_2015__03","osVersionType:Amazon_Linux_2015__09","osVersionType:Amazon_Linux_2016__03","osVersionType:Amazon_Linux_2016__09","osVersionType:Amazon_Linux_2017__03","osVersionType:Debian_Linux_8","osVersionType:Debian_Linux_9","outdated:true","outdated:false","pendingActions:<array so it can be defined more than once>","policyId:<string>","policyName:<string>","powerShellStatus:PS_DISABLED","powerShellStatus:PS_ENABLED","powerShellStatus:PS_DEFAULT","preventionError:<string>","preventionStatus:ENABLE","preventionStatus:DISABLE","preventionStatus:UNINSTALL","preventionStatus:UNKNOWN","proxyAddress:<ipaddress>","pylumID:<string>","quickScanStatus","ransomwareStatus:UNKNOWN","ransomwareStatus:DISABLED","ransomwareStatus:DETECT_ONLY","ransomwareStatus:DETECT_AND_SUSPEND","ransomwareStatus:DETECT_SUSPEND_PREVENT","remoteShellStatus:AC_DISABLED","remoteShellStatus:AC_ENABLED","sensorId:<string>","sensorArchivedByUser:<string>","sensorLastUpdate:<timestamp>","serverId:<string>","serverName:<string>","serviceStatus:DISABLED","serviceStatus:DETECT","serviceStatus:PREVENT","serviceStatus:SET_BY_POLICY","siteName:<string>","siteId:<long>","staleTimeMS:<time in epoch>","staticAnalysisDetectMode:DISABLED","staticAnalysisDetectMode:CAUTIOUS","staticAnalysisDetectMode:MODERATE","staticAnalysisDetectMode:AGGRESSIVE","staticAnalysisDetectMode:SET_BY_POLICY","staticAnalysisDetectModeOrigin:NOT_AVAILBLE","staticAnalysisDetectModeOrigin:SET_BY_POLICY","staticAnalysisDetectModeOrigin:SET_MANUALLY","staticAnalysisDetectModeOrigin:AWAITING_UPDATE","staticAnalysisPreventMode:DISABLED","staticAnalysisPreventMode:CAUTIOUS","staticAnalysisPreventMode:MODERATE","staticAnalysisPreventMode:AGGRESSIVE","staticAnalysisPreventModeOrigin:NOT_AVAILBLE","staticAnalysisPreventModeOrigin:SET_BY_POLICY","staticAnalysisPreventModeOrigin:SET_MANUALLY","staticAnalysisPreventModeOrigin:AWAITING_UPDATE","status:Online","status:Offline","status:Stale","status:Archived","statusTimeMS:<timestamp>","upTime:<Long>","usbStatus:ENABLED","usbStatus:DISABLED","version:<string sensor version number>")]
            [String]$Filter

        )  # End param

    $Uri = 'https://' + $Server + ':' + $Port + '/rest/sensors/query'
    # '{"limit":' + $Limit + ',"offset":"' + $Offset + '","sortDirection":"' + $Sort + '","filters":[{"fieldName":filter_1_name,"operator":"Equals","values":[filter_1_value]}]})})'
    $JsonData = '{"limit":' + $Limit + ',"offset":' + $Offset + ',"sortDirection":"' + $Sort + '","filters":[{'
    $FieldName,$Values = $Filter.Split(":")
    $Value = $Values.Split(",").Trim()
    $JsonData = $JsonData + "`"fieldName`":`"$FieldName`",`"operator`":`"Equals`",`"values`":[`"$Value`"]}]})"

    Write-Verbose "Sending query to $Uri"
    $Response = Invoke-WebRequest -Method POST -ContentType 'application/json' -Uri $Uri -WebSession $CybereasonSession -Body $JsonData

    $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty sensors | `
            ForEach-Object {
                $SensorId = ($_.sensorId | Out-String).Trim()
                $pylumId = ($_.pylumId | Out-String).Trim()
                $guid = ($_.guid | Out-String).Trim()
                $fqdn = ($_.fqdn | Out-String).Trim()
                $machineName = ($_.machineName | Out-String).Trim()
                $internalIpAddress = ($_.internalIpAddress | Out-String).Trim()
                $externalIpAddress = ($_.externalIpAddress | Out-String).Trim()
                $siteName = ($_.siteName | Out-String).Trim()
                $siteId = ($_.siteId | Out-String).Trim()
                $ransomwareStatus = ($_.ransomwareStatus | Out-String).Trim()
                $preventionStatus = $_.preventionStatus
                $isolated = ($_.isolated | Out-String).Trim()
                $disconnectionTime = Get-Date -Date ($_.disconnectionTime)
                $lastPylumInfoMsgUpdateTime = Get-Date -Date ($_.lastPylumInfoMsgUpdateTime)
                $status = ($_.status | Out-String).Trim()
                $onlineTimeMS = Get-Date -Date ($_.onlineTimeMS)
                $offlineTimeMS = Get-Date -Date ($_.offlineTimeMS)
                $staleTimeMS = Get-Date -Date ($_.staleTimeMS)
                $archiveTimeMs = Get-Date -Date ($_.archiveTimeMs)
                $statusTimeMS = Get-Date -Date ($_.statusTimeMS)
                $lastStatusAction = ($_.lastStatusAction | Out-String).Trim()
                $archivedOrUnarchiveComment = ($_.archivedOrUnarchiveComment | Out-String).Trim()
                $sensorArchivedByUser = ($_.sensorArchivedByUser | Out-String).Trim()
                $serverName = ($_.serverName | Out-String).Trim()
                $serverId = ($_.serverId | Out-String).Trim()
                $osType = ($_.osType | Out-String).Trim()
                $osVersionType = ($_.osVersionType | Out-String).Trim()
                $collectionStatus = ($_.collectionStatus | Out-String).Trim()
                $version = ($_.version | Out-String).Trim()
                $firstSeenTime = Get-Date -Date ($_.firstSeenTime)
                $upTime = Get-Date -Date ($_.upTime)
                $cpuUsage = ($_.cpuUsage | Out-String).Trim()
                $memoryUsage = ($_.memoryUsage | Out-String).Trim()
                $outdated = ($_.outdated | Out-String).Trim()
                $amStatus = ($_.amStatus | Out-String).Trim()
                $powerShellStatus = ($_.powerShellStatus | Out-String).Trim()
                $antiMalwareStatus = ($_.antiMalwareStatus | Out-String).Trim()
                $organization = ($_.organization | Out-String).Trim()
                $proxyAddress = ($_.proxyAddress | Out-String).Trim()
                $preventionError = ($_.preventionError | Out-String).Trim()
                $exitReason = ($_.exitReason | Out-String).Trim()
                $actionsInProgress = ($_.actionsInProgress | Out-String).Trim()
                $pendingActions = ($_.pendingActions | Out-String).Trim()
                $lastUpgradeResult = ($_.lastUpgradeResult | Out-String).Trim()
                $lastUpgradeSteps = ($_.lastUpgradeSteps | Out-String).Trim()
                $disconnected = ($_.disconnected | Out-String).Trim()
                $sensorLastUpdate = Get-Date -Date ($_.sensorLastUpdate)
                $fullScanStatus = ($_.fullScanStatus | Out-String).Trim()
                $quickScanStatus = ($_.quickScanStatus | Out-String).Trim()
                $lastFullScheduleScanSuccessTime = Get-Date -Date ($_.lastFullScheduleScanSuccessTime)
                $lastQuickScheduleScanSuccessTime = Get-Date -Date ($_.lastQuickScheduleScanSuccessTime)

                $Obj += New-Object -TypeName PSObject -Property @{sensorId=$sensorId; pylumId=$pylumId; guid=$guid; fqdn=$fqdn; machineName=$machineName; internalIpAddress=$internalIpAddress; externalIpAddress=$externalIpAddress; siteName=$siteName;siteId=$siteId;ransomwareStatus=$ransomwareStatus;preventionStatus=$preventionStatus;isolated=$isolated;disconnectionTime=$disconnectionTime;lastPylumInfoMsgUpdateTime=$lastPylumInfoMsgUpdateTime;status=$status;onlineTimeMS=$onlineTimeMS;offlineTimeMS=$offlineTimeMS;staleTimeMS=$staleTimeMS;archiveTimeMs=$archiveTimeMs;statusTimeMS=$statusTimeMS;lastStatusAction=$lastStatusAction;archivedOrUnarchiveComment=$archivedOrUnarchiveComment;sensorArchivedByUser=$sensorArchivedByUser;serverName=$serverName;serverId=$serverId;osType=$osType;osVersionType=$osVersionType;collectionStatus=$collectionStatus;version=$version;firstSeenTime=$firstSeenTime;upTime=$upTime;cpuUsage=$cpuUsage;memoryUsage=$memoryUsage;outdated=$outdated;amStatus=$amStatus;powerShellStatus=$powerShellStatus;antiMalwareStatus=$antiMalwareStatus;organization=$organization;proxyAddress=$proxyAddress;preventionError=$preventionError;exitReason=$exitReason;actionsInProgress=$actionsInProgress;pendingActions=$pendingActions;lastUpgradeResult=$lastUpgradeResult;lastUpgradeSteps=$lastUpgradeSteps;disconnected=$disconnected;sensorLastUpdate=$sensorLastUpdate;fullScanStatus=$fullScanStatus;quickScanStatus=$quickScanStatus;lastFullScheduleScanSuccessTime=$lastFullScheduleScanSuccessTime;lastQuickScheduleScanSuccessTime=$lastQuickScheduleScanSuccessTime}  # End Properties

            }  # End ForEach-Object

            $Obj

}  # End Function Get-CybereasonListAllSensors
# SIG # Begin signature block
# MIIM9AYJKoZIhvcNAQcCoIIM5TCCDOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU86iHllSzEFVz0aZHh8PbJflJ
# zASgggn7MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
# BhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAY
# BgNVBAoTEUdvRGFkZHkuY29tLCBJbmMuMTEwLwYDVQQDEyhHbyBEYWRkeSBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTExMDUwMzA3MDAwMFoXDTMx
# MDUwMzA3MDAwMFowgbQxCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMw
# EQYDVQQHEwpTY290dHNkYWxlMRowGAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjEt
# MCsGA1UECxMkaHR0cDovL2NlcnRzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMTMw
# MQYDVQQDEypHbyBEYWRkeSBTZWN1cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0g
# RzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC54MsQ1K92vdSTYusw
# ZLiBCGzDBNliF44v/z5lz4/OYuY8UhzaFkVLVat4a2ODYpDOD2lsmcgaFItMzEUz
# 6ojcnqOvK/6AYZ15V8TPLvQ/MDxdR/yaFrzDN5ZBUY4RS1T4KL7QjL7wMDge87Am
# +GZHY23ecSZHjzhHU9FGHbTj3ADqRay9vHHZqm8A29vNMDp5T19MR/gd71vCxJ1g
# O7GyQ5HYpDNO6rPWJ0+tJYqlxvTV0KaudAVkV4i1RFXULSo6Pvi4vekyCgKUZMQW
# OlDxSq7neTOvDCAHf+jfBDnCaQJsY1L6d8EbyHSHyLmTGFBUNUtpTrw700kuH9zB
# 0lL7AgMBAAGjggEaMIIBFjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB
# BjAdBgNVHQ4EFgQUQMK9J47MNIMwojPX+2yz8LQsgM4wHwYDVR0jBBgwFoAUOpqF
# BxBnKLbv9r0FQW4gwZTaD94wNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5nb2RhZGR5LmNvbS8wNQYDVR0fBC4wLDAqoCigJoYkaHR0cDov
# L2NybC5nb2RhZGR5LmNvbS9nZHJvb3QtZzIuY3JsMEYGA1UdIAQ/MD0wOwYEVR0g
# ADAzMDEGCCsGAQUFBwIBFiVodHRwczovL2NlcnRzLmdvZGFkZHkuY29tL3JlcG9z
# aXRvcnkvMA0GCSqGSIb3DQEBCwUAA4IBAQAIfmyTEMg4uJapkEv/oV9PBO9sPpyI
# BslQj6Zz91cxG7685C/b+LrTW+C05+Z5Yg4MotdqY3MxtfWoSKQ7CC2iXZDXtHwl
# TxFWMMS2RJ17LJ3lXubvDGGqv+QqG+6EnriDfcFDzkSnE3ANkR/0yBOtg2DZ2HKo
# cyQetawiDsoXiWJYRBuriSUBAA/NxBti21G00w9RKpv0vHP8ds42pM3Z2Czqrpv1
# KrKQ0U11GIo/ikGQI31bS/6kA1ibRrLDYGCD+H1QQc7CoZDDu+8CL9IVVO5EFdkK
# rqeKM+2xLXY2JtwE65/3YR8V3Idv7kaWKK2hJn0KCacuBKONvPi8BDABMIIFIzCC
# BAugAwIBAgIIXIhNoAmmSAYwDQYJKoZIhvcNAQELBQAwgbQxCzAJBgNVBAYTAlVT
# MRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMRowGAYDVQQK
# ExFHb0RhZGR5LmNvbSwgSW5jLjEtMCsGA1UECxMkaHR0cDovL2NlcnRzLmdvZGFk
# ZHkuY29tL3JlcG9zaXRvcnkvMTMwMQYDVQQDEypHbyBEYWRkeSBTZWN1cmUgQ2Vy
# dGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwHhcNMjAxMTE1MjMyMDI5WhcNMjExMTA0
# MTkzNjM2WjBlMQswCQYDVQQGEwJVUzERMA8GA1UECBMIQ29sb3JhZG8xGTAXBgNV
# BAcTEENvbG9yYWRvIFNwcmluZ3MxEzARBgNVBAoTCk9zYm9ybmVQcm8xEzARBgNV
# BAMTCk9zYm9ybmVQcm8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJ
# V6Cvuf47D4iFITUSNj0ucZk+BfmrRG7XVOOiY9o7qJgaAN88SBSY45rpZtGnEVAY
# Avj6coNuAqLa8k7+Im72TkMpoLAK0FZtrg6PTfJgi2pFWP+UrTaorLZnG3oIhzNG
# Bt5oqBEy+BsVoUfA8/aFey3FedKuD1CeTKrghedqvGB+wGefMyT/+jaC99ezqGqs
# SoXXCBeH6wJahstM5WAddUOylTkTEfyfsqWfMsgWbVn3VokIqpL6rE6YCtNROkZq
# fCLZ7MJb5hQEl191qYc5VlMKuWlQWGrgVvEIE/8lgJAMwVPDwLNcFnB+zyKb+ULu
# rWG3gGaKUk1Z5fK6YQ+BAgMBAAGjggGFMIIBgTAMBgNVHRMBAf8EAjAAMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIHgDA1BgNVHR8ELjAsMCqgKKAm
# hiRodHRwOi8vY3JsLmdvZGFkZHkuY29tL2dkaWcyczUtNi5jcmwwXQYDVR0gBFYw
# VDBIBgtghkgBhv1tAQcXAjA5MDcGCCsGAQUFBwIBFitodHRwOi8vY2VydGlmaWNh
# dGVzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMAgGBmeBDAEEATB2BggrBgEFBQcB
# AQRqMGgwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmdvZGFkZHkuY29tLzBABggr
# BgEFBQcwAoY0aHR0cDovL2NlcnRpZmljYXRlcy5nb2RhZGR5LmNvbS9yZXBvc2l0
# b3J5L2dkaWcyLmNydDAfBgNVHSMEGDAWgBRAwr0njsw0gzCiM9f7bLPwtCyAzjAd
# BgNVHQ4EFgQUkWYB7pDl3xX+PlMK1XO7rUHjbrwwDQYJKoZIhvcNAQELBQADggEB
# AFSsN3fgaGGCi6m8GuaIrJayKZeEpeIK1VHJyoa33eFUY+0vHaASnH3J/jVHW4BF
# U3bgFR/H/4B0XbYPlB1f4TYrYh0Ig9goYHK30LiWf+qXaX3WY9mOV3rM6Q/JfPpf
# x55uU9T4yeY8g3KyA7Y7PmH+ZRgcQqDOZ5IAwKgknYoH25mCZwoZ7z/oJESAstPL
# vImVrSkCPHKQxZy/tdM9liOYB5R2o/EgOD5OH3B/GzwmyFG3CqrqI2L4btQKKhm+
# CPrue5oXv2theaUOd+IYJW9LA3gvP/zVQhlOQ/IbDRt7BibQp0uWjYaMAOaEKxZN
# IksPKEJ8AxAHIvr+3P8R17UxggJjMIICXwIBATCBwTCBtDELMAkGA1UEBhMCVVMx
# EDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNVBAoT
# EUdvRGFkZHkuY29tLCBJbmMuMS0wKwYDVQQLEyRodHRwOi8vY2VydHMuZ29kYWRk
# eS5jb20vcmVwb3NpdG9yeS8xMzAxBgNVBAMTKkdvIERhZGR5IFNlY3VyZSBDZXJ0
# aWZpY2F0ZSBBdXRob3JpdHkgLSBHMgIIXIhNoAmmSAYwCQYFKw4DAhoFAKB4MBgG
# CisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcC
# AQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYE
# FI0TjOxxmhUMx8fI/Va3rxKXICv0MA0GCSqGSIb3DQEBAQUABIIBABLjD2Lf7m70
# Pr9URKLbTYSdtOgeu/tCsEKEDdGxtCldN8EPQxVgJ3w/X9Cy5r0yFDb37izgdesY
# lrfmgt2P7TMKJoKq/4ZtyzPoIpiyJWy8Xgzz+91C3M4lUAsK6zNXE7zgdHnvf7Cr
# kWNGGvtvJ8aqpLaN+J88Rj7iHc+gRZ/gndKfBOoiJGV+e5IXY6k42ExehBtRUi8g
# sR/qYthBFUONafjxKOquJlQwAR8TR6HBN2XNFZZ0rcmf3AAGBOG8rruYs9SjepcH
# iA7pwkx+AsVdBUVKCScOqDyX8Ppx+gNftfAtjeAblixpP+HFQHujzS6hkUJ1YUCS
# 6kovc1U3+oc=
# SIG # End signature block
