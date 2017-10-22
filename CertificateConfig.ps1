<# 
This script will loop through each of the lines in the csv file and create a certificate Config file for each item.
Some certificates will require additional SAN names with many DNS entries. Each DNS entry is a short DNS name. 
To obtain the FQDN the selected Domain name is appended to the end of each DNS entry.
Most certificate Config files will only require the default Configuration with a single DNS/FQDN SAN entry. 
#> 

## Import the CSV file and set the output directory for the Config files 
#$Config = Import-CSV (Read-Host "Enter the path the CertificateConfig CSV file: ")
$Content = Get-Content (Read-Host "Enter the path the CertificateConfig CSV file: ") 
$Config = ConvertFrom-Csv $Content
$FilePath = (Get-Location).ProviderPath + "\ConfigFiles"

## Set Default Configuration details for certificate files
$ORG = Read-Host "Enter the Organisation [LabRat]: "
	if (!$ORG) {$ORG = "LabRat"}
$OU = Read-Host "Enter the Organisation Unit [HomeLab]: "
	if (!$OU) {$OU = "HomeLab"}
$LOCATION = Read-Host "Enter the Location/Datacenter [Canberra]: "
	if (!$LOCATION) {$LOCATION = "Canberra"}
$STATE = Read-Host "Enter the State [ACT]: "
	if (!$STATE) {$STATE = "ACT"}
$COUNTRY = Read-Host "Enter the Country [AU]: "
	if (!$COUNTRY) {$COUNTRY = "AU"}
$KEYSIZE = Read-Host "Enter the key size [2048]: "
	if (!$KEYSIZE) {$KEYSIZE = "2048"}

## If the ConfigFiles directory doesn't exist, create it.
If (!(Test-Path $FilePath)){New-Item -ItemType Directory -Path $FilePath -Force}

## Loop through each line in the CSV file (which represents a different certificate)
ForEach ($Certificate in $Config){
	$Name = $Certificate.Name
	$FileName = $Certificate.FileName + $LocationName + ".txt"
	$Domain = $Certificate.Domain
	$IP = $Certificate.IPAddress
    If (!($Certificate.DNS1)) {continue}
	$DNS = $Certificate.DNS1
	$DNS = $DNS.split('.')[0]
    $FQDN = $DNS+"."+$Domain

## Create a new Config file that includes the chosen default settings and the configuration details for each certificate.	
    Write-Host "Creating SSL certificate config file: " $FileName
    Set-Content $FilePath\$FileName -Force `
"[CERT]
NAME=$FQDN
ORG=$ORG
OU=$OU
LOC=$LOCATION
ST=$STATE
CC=$COUNTRY
CN=$FQDN
keysize=$KEYSIZE
[SAN]"

## If the certificate contains more than one DNS alternate name or IP address then they will be added to the [SAN] list
    Foreach ($Property in ($Certificate | Get-Member | Where {(($_.Name -like "DNS*") -or ($_.Name -like "IP*"))})){
        If ($Property.Name -like "DNS*"){
            $DNS = $Certificate.$($Property.name)
            If ($DNS){
                $DNS = $DNS.split('.')[0]
                Add-Content $FilePath\$FileName -Force `
"$DNS
$DNS.$Domain"
            }
        }
        If ($Property.Name -like "IP*"){
            $IP = $Certificate.$($Property.name)
            If ($IP){
                Add-Content $FilePath\$FileName `
"#IP Address
$IP"        
            }
        }
    }
}
Write-Host ""
Write-Host "Certificate config files have been created in: " $FilePath -BackgroundColor Yellow -ForegroundColor Black