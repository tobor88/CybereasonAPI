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
Get-CybereasonThreatIntel -Md5Hash (Get-FileHash -Algorithm MD5 -Path C:\Users\Public\Desktop\AlwaysInstallElevatedCheck.htm).Hash
# This example gets the file hash of a file on the OS and determines if it is malicious or not

.EXAMPLE
Get-CybereasonThreatIntel -FileToHash C:\Windows\System32\cmd.exe
# This example returns details on the file C:\Windows\System32\cmd.exe's reputation based on the Cybereason threat intelligence service. This determines the MD5 hash automatically of the file you define. If you already have the hash enter it using the -Md5Hash parameter instead of this one.

.EXAMPLE
Get-CybereasonThreatIntel -Domain www.cybereason.com
# This example returns details on domain reputations for www.cybereason.com based on the Cybereason threat intelligence service.

.EXAMPLE
Get-CybereasonThreatIntel -IPAddress 1.1.1.1
# This example returns details on IP address reputations for 1.1.1.1 based on the Cybereason threat intelligence service. 

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
            [String]$Md5Hash,

            [Parameter(
                ParameterSetName='FileToHash',
                Mandatory=$True,
                ValueFromPipeline=$False)]  # End Parameter
            [String]$FileToHash,

            [Parameter(
                ParameterSetName='Domain',
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Define a domain to look up threat information on`n[E] EXAMPLE: www.cybereason.com")]  # End Parameter
            [String]$Domain,

            [Parameter(
                ParameterSetName='IPAddress',
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Define an IP Address to look up threat information on`n[E] EXAMPLE: 1.1.1.1")]  # End Parameter
            [String]$IPAddress,

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
            $JsonData = '{"requestData": [{"requestKey": {"md5": "' + $Md5Hash + '"} }] }'

            Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

            $Results = $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty "classificationResponses"
            $MD5 = ($Results.requestKey.md5 | Out-String).Trim()
            $SHA1 = ($Results.requestKey.sha1 | Out-String).Trim()
            $MaliciousScore = $Results.aggregatedResult.maliciousClassification
            $ProductType = ($Results.aggregatedResult.productClassification.productType | Out-String).Trim()
            $Type = ($Results.aggregatedResult.productClassification.Type | Out-String).Trim()
            $Obj += New-Object -TypeName PSObject -Property @{md5="$MD5"; sha1="$SHA1"; MaliciousScore="$MaliciousScore"; ProductType="$ProductType"; Type="$Type"}

            $Obj

        }  # End Switch FileRep

        'FileToHash' {

            $Uri = $Site + 'classification_v1/file_batch'
            If (!(Test-Path -Path $FileToHash))
            {

                Throw "[!] The file path you defined could not be found"

            }  # End If

            $FileHash = (Get-FileHash -Algorithm MD5 -Path $FileToHash).Hash
            $JsonData = '{"requestData": [{"requestKey": {"md5": "' + $FileHash + '"} }] }'

            Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

            $Results = $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty "classificationResponses"
            $MD5 = ($Results.requestKey.md5 | Out-String).Trim()
            $SHA1 = ($Results.requestKey.sha1 | Out-String).Trim()
            $MaliciousScore = $Results.aggregatedResult.maliciousClassification
            $ProductType = ($Results.aggregatedResult.productClassification.productType | Out-String).Trim()
            If ($SHA1.Length -ne 40) { $SHA1 = ((Get-FileHash -Algorithm SHA1 -Path $FileToHash).Hash).Trim() }
            $Type = ($Results.aggregatedResult.productClassification.Type | Out-String).Trim()

            $Obj += New-Object -TypeName PSObject -Property @{md5="$MD5"; sha1="$SHA1"; MaliciousScore="$MaliciousScore"; ProductType="$ProductType"; Type="$Type"}

            $Obj

        }  # End Switch FileRep

        'IPAddress' {

            $Uri = $Site + 'classification_v1/ip_batch'
            $IPv4Regex = '(((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))'

            Write-Verbose "Testing $IPAddress"

            $Obj = @()
            If ($IPAddress -Match $IPv4Regex)
            {

                $IPType = 'Ipv4'

            }  # End If
            Else 
            {

                $IPType = 'Ipv6'

            }  # End Else
            $JsonData = '{"requestData": [{"requestKey": {"ipAddress": "' + $IPAddress + '","addressType": "' + $IPType + '"} }] }' 

            Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

            $Results = $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty "classificationResponses"
            $IPAddres = ($Results.requestKey.ipAddress | Out-String).Trim()
            $AddressType = ($Results.requestKey.addressType | Out-String).Trim()
            $MaliciousScore = $Results.aggregatedResult.maliciousClassification
            $FirstSeen = Get-Date ($Results.aggregatedResult.firstSeen)
            $AllowFurther = ($Results.allowFurtherClassification | Out-String).Trim()
            $CPID = ($Results.cpId | Out-String).Trim()

            $Obj += New-Object -TypeName PSObject -Property @{IP=$IPAddres; Type=$AddressType; MaliciousScore=$MaliciousScore; FirstSeen=$FirstSeen; AllowFurtherClassification=$AllowFurther; CPID=$CPID}

            $Obj   

        }  # End Switch IPBat

        'Domain' {

            $Uri = $Site + 'classification_v1/domain_batch'

            Write-Verbose "Testing $Domain"

            $JsonData = '{"requestData": [{"requestKey": {"domain": "' + $Domain + '"} }] }'

            Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

            $Results = $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty "classificationResponses"

            $Dom = ($Results.requestKey.domain | Out-String).Trim()
            $Source = ($Results.aggregatedResult.maliciousClassification.source | Out-String).Trim()
            $MaliciousScore = $Results.aggregatedResult.maliciousClassification
            $FirstSeen = Get-Date -Date ($Results.aggregatedResult.firstSeen)
            $AllowFurther = ($Results.allowFurtherClassification | Out-String).Trim()
            $CPID = ($Results.cpId | Out-String).Trim()
            $CPType = ($Results.cpType | Out-String).Trim()

            $Obj += New-Object -TypeName PSObject -Property @{Domain=$Dom; Source=$Source; MaliciousScore=$MaliciousScore; FirstSeen=$FirstSeen; AllowFurtherClassification=$AllowFurther; CPID=$CPID; CPType=$CPType}

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