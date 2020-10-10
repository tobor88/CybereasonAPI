<#
.SYNOPSIS
This cmdlet was created to quickly and easily look up threat information on an IP address or domain using the Cybereason API.


.DESCRIPTION
Easily and quickly communicate with the Cyberason API to discover threat intel on an IP address or domain


.PARAMETER Md5Hash
This parameter accepts an MD5 hash of a file to check the reputation of against the Cybereason database

.PARAMETER FileToHash
This parameter defines a file that you want to check against the cybereason reputation database. If you do not have the hash of the file this will automtically get the hash for you and check it's reputation

.PARAMETER Domain
This parameter defines the domain to be checked on

.PARAMETER IPAddress
This parameter defines the IP address to be checked on

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

.PARAMETER IPRep
This switch parameter indicates you wish to retrieve a list of IP address reputations 

.PARAMETER DomainRep
This switch parameter indicates you wish to retrieve a list of domain reputations

.PARAMETER DbUpdateCheck
This switch parameter indicates you wish to check for database updates 


.EXAMPLE
Get-ThreatIntel -Md5Hash 'D7AB69FAD18D4A643D84A271DFC0DBDF'
# This example returns details on a file’s reputation based on the Cybereason threat intelligence service using the MD5 hash. If you do not already have the hash, use the -FileToHash parameter to have it obtained automtacilly for you.

.EXAMPLE
Get-ThreatIntel -Md5Hash (Get-FileHash -Algorithm MD5 -Path C:\Users\Public\Desktop\AlwaysInstallElevatedCheck.htm).Hash
# This example gets the file hash of a file on the OS and determines if it is malicious or not

.EXAMPLE
Get-ThreatIntel -FileToHash C:\Windows\System32\cmd.exe
# This example returns details on the file C:\Windows\System32\cmd.exe's reputation based on the Cybereason threat intelligence service. This determines the MD5 hash automatically of the file you define. If you already have the hash enter it using the -Md5Hash parameter instead of this one.

.EXAMPLE
Get-ThreatIntel -Domain www.cybereason.com
# This example returns details on domain reputations for www.cybereason.com based on the Cybereason threat intelligence service.

.EXAMPLE
Get-ThreatIntel -IPAddress 1.1.1.1
# This example returns details on IP address reputations for 1.1.1.1 based on the Cybereason threat intelligence service. 

.EXAMPLE
Get-ThreatIntel -DbUpdateCheck
# The rest of the options are all switch parameters and do not have any values to enter. As such I am not going to do this for every single one. The -DbUpdateCheck switch parameter checks fro Cybereason sensor updates that are available

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
Function Get-ThreatIntel {
    [CmdletBinding()]
        param(
            [Parameter(
                ParameterSetName='FileRep1',
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [String]$Md5Hash,

            [Parameter(
                ParameterSetName='FileRep2',
                Mandatory=$False,
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
                ParameterSetName='IPRep')]  # End Parameter
            [Switch][Bool]$IPRep,

            [Parameter(
                ParameterSetName='DomainRep')]  # End Parameter
            [Switch][Bool]$DomainRep,

            [Parameter(
                ParameterSetName='DbUpdateCheck')]  # End Parameter
            [Switch][Bool]$DbUpdateCheck

        )  # End param

    $Obj = @()
    $Site = 'https://sage.cybereason.com/rest/'
    $PSBoundParameters.Keys
    Switch ($PSBoundParameters.Keys)
    {

        'FileRep1' {

            $Uri = $Site + 'classification_v1/file_batch'
            $JsonData = '{"requestData": [{"requestKey": {"md5": "' + $Md5Hash + '"} }] }'

            Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

            $Results = $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty "classificationResponses"
            $MD5 = $Results.requestKey.md5 | Out-String 
            $SHA1 = $Results.requestKey.sha1 | Out-String 
            $MaliciousScore = $Results.aggregatedResult.maliciousClassification
            $ProductType = $Results.aggregatedResult.productClassification.productType | Out-String
            $Type = $Results.aggregatedResult.productClassification.Type | Out-String

            $Obj += New-Object -TypeName PSObject -Property @{md5="$MD5"; sha1="$SHA1"; MaliciousScore="$MaliciousScore"; ProductType="$ProductType"; Type="$Type"}

            $Obj

        }  # End Switch FileRep

        'FileRep2' {

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
            $MD5 = $Results.requestKey.md5 | Out-String 
            $SHA1 = $Results.requestKey.sha1 | Out-String 
            $MaliciousScore = $Results.aggregatedResult.maliciousClassification
            $ProductType = $Results.aggregatedResult.productClassification.productType | Out-String
            $Type = $Results.aggregatedResult.productClassification.Type | Out-String

            $Obj += New-Object -TypeName PSObject -Property @{md5="$MD5"; sha1="$SHA1"; MaliciousScore="$MaliciousScore"; ProductType="$ProductType"; Type="$Type"}

            $Obj

        }  # End Switch FileRep

        'IPAddress' {

            $Uri = $Site + 'classification_v1/ip_batch'
            $IPv4Regex = '(((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))'

            Write-Verbose "Testing $IPAddress"

            $Obj = @()
            If ($IpA -Match $IPv4Regex)
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
            $IPAddress = $Results.requestKey.ipAddress | Out-String
            $AddressType = $Results.requestKey.addressType | Out-String
            $MaliciousScore = $Results.aggregatedResult.maliciousClassification
            $FirstSeen = Get-Date ($Results.aggregatedResult.firstSeen) 
            $AllowFurther = $Results.allowFurtherClassification | Out-String
            $CPID = $Results.cpId | Out-String

            $Obj += New-Object -TypeName PSObject -Property @{IP=$IPAddress; Type=$AddressType; MaliciousScore=$MaliciousScore; FirstSeen=$FirstSeen; AllowFurtherClassification=$AllowFurther; CPID=$CPID}

            $Obj   

        }  # End Switch IPBat

        'Domain' {

            $Uri = $Site + 'classification_v1/domain_batch'

            Write-Verbose "Testing $D"

            $JsonData = '{"requestData": [{"requestKey": {"domain": "' + $D + '"} }] }'

            Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

            $Results = $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty "classificationResponses"

            $Dom = $Results.requestKey.domain | Out-String
            $Source = $Results.aggregatedResult.maliciousClassification.source | Out-String
            $MaliciousScore = $Results.aggregatedResult.maliciousClassification
            $FirstSeen = Get-Date ($Results.aggregatedResult.firstSeen) 
            $AllowFurther = $Results.allowFurtherClassification | Out-String
            $CPID = $Results.cpId | Out-String
            $CPType = $Results.cpType | Out-String

            $Obj += New-Object -TypeName PSObject -Property @{Domain=$Dom; Source=$Source; MaliciousScore=$MaliciousScore; FirstSeen=$FirstSeen; AllowFurtherClassification=$AllowFurther; CPID=$CPID; CPType=$CPType}

            $Obj
 
        }  # End Switch DomainBatch
        
        'ProductClassification' {

            $Uri = $Site + 'download_v1/productClassifications'
            $JsonData = "{}"

            Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

            $Results = $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty "recordList"
            For ($i = 0; $i -le $Results.Count; $i++)
            {

                $Name = $Results.Key.name[$i] | Out-String
                $Signer = $Results.Value.signer[$i] | Out-String
                $Type = $Results.Value.type[$i] | Out-String
                $Title = $Results.Value.title[$i] | Out-String

                $Obj += New-Object -TypeName PSObject -Property @{Name="$Name"; Signer=$Signer; Type=$Type; Title="$Title"}

            }  # End For

            $Obj

        }  # End Switch ProductClassification

        'ProcessClassification' {

            $Uri = $Site + 'download_v1/process_classification'
            $JsonData = "{}"

            Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

            $Results = $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty "recordList"
            For ($i = 0; $i -le $Results.Count; $i++)
            {

                $ProcessName = $Results.Key.name[$i] | Out-String
                $Title = $Results.Value.title[$i] | Out-String
                $ProductName = $Results.Value.productName[$i] | Out-String
                $CompanyName = $Results.Value.companyName[$i] | Out-String
                $fileDescription = $Results.Value.fileDescription[$i] | Out-String
                $filePath = $Results.Value.path[$i] | Out-String


                $Obj += New-Object -TypeName PSObject -Property @{ProcessName="$ProcessName"; Title="$Title"; ProductName=$ProductName; CompanyName=$CompanyName; FileDescription=$fileDescription; FilePath=$FilePath}

            }  # End For

            $Obj

        }  # End Switch ProcessClassification

        'ProcessHierarchy' {

            $Uri = $Site + 'download_v1/process_hierarchy'
            $JsonData = "{}"

            Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

            $Results = $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty "recordList"
            For ($i = 0; $i -le $Results.Count; $i++)
            {

                $Parent = $Results.Value.parent[$i] | Out-String
                $ProcessName = $Results.Key.name[$i] | Out-String

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

            $Results = $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty "recordList" 
            For ($i = 0; $i -le $Results.Count; $i++)
            {

                $Port = $Results.Key.port[$i] | Out-String
                $Protocol = $Results.Key.protocol[$i] | Out-String
                $Type = $Results.Value.type[$i] | Out-String
                $ShortDescription = $Results.Value.shortDescription[$i] | Out-String
                $Source = $Results.Value.sources[$i] | Out-String
                $LongDescr = $Results.Value.longDescription[$i] | Out-String

                $Obj += New-Object -TypeName PSObject -Property @{Port="$Port"; Protocol="$Protocol"; Type=$Type; ShortDescription=$ShortDescription; Source=$Source; LongDescription=$LongDescr}

            }  # End For

            $Obj

        }  # End Switch PortInfo

        'CollectionInfo' {

            $Uri = $Site + 'download_v1/const'
            $JsonData = "{}"

            Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

            $Results = $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty "recordList"
            For ($i = 0; $i -le $Results.Count; $i++)
            {

                $Name = $Results.Key.name[$i] | Out-String
                $Data = $Results.Value.data[$i] | Out-String

                $Obj += New-Object -TypeName PSObject -Property @{Name="$Name"; Data="$Data"}

            }  # End For 
            
            $Obj

        }  # End Switch CollectionInfo

        'IPRep' {

            $Uri = $Site + 'download_v1/ip_reputation'
            $JsonData = "{}"

            Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

            $Results = $Response.Content | ConvertFrom-Json
            For ($i = 0; $i -le $Results.ipReputationResponseList.Count; $i++)
            {

                $IPAddress = $Results.ipReputationResponseList.requestkey.ipaddress[$i] | Out-String
                $AddressType = $Results.ipReputationResponseList.requestkey.addressType[$i] | Out-String
                $ReputationSource = $Results.ipReputationResponseList.aggregatedResult.reputationSource[$i] | Out-String
                $ReputationScore = $Results.ipReputationResponseList.aggregatedResult.reputationScore[$i] | Out-String

                $Obj += New-Object -TypeName PSObject -Property @{IPAddress="$IPAddress"; AddressType="$AddressType"; ReputationSource="$ReputationSource"; ReputationScore="$ReputationScore"}

            }  # End For 
            
            $Obj

        }  # End IPRep Switch

        'DomainRep' {

            $Uri = $Site + 'download_v1/domain_reputation'
            $JsonData = "{}"

            Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

            $Results = $Response.Content | ConvertFrom-Json
            For ($i = 0; $i -le $Results.ipReputationResponseList.Count; $i++)
            {

                $Domain = $Results.domainReputationResponseList.requestkey[$i] | Out-String
                $ReputationSource = $Results.domainReputationResponseList.aggregatedResult.reputationSource[$i] | Out-String
                $ReputationScore = $Results.domainReputationResponseList.aggregatedResult.reputationScore[$i] | Out-String

                $Obj += New-Object -TypeName PSObject -Property @{Domain="$Domain"; ReputationSource="$ReputationSource"; ReputationScore="$ReputationScore"}

            }  # End For
            
            $Obj 
        
        }  #End Switch DomainRep

        'DbUpdateCheck' {

            $Uri = $Site + 'download_v1/:%20API+name/service'
            $JsonData = "{}"

            Write-Verbose "Sending THreat Intel JSON data to Cybereason's API"
            $Response = Invoke-WebRequest -Uri $Uri -Method POST -ContentType "application/json" -Body $JsonData 

            $Results = $Response.Content | ConvertFrom-Json | Select-Object -ExpandProperty "recordList" 
            
            $Obj

        }  # End Switch DbUpdateCheck

    }  # End Switch

}  # End Function Get-ThreatIntel