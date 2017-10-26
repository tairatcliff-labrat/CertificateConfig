<#
Author: Ramya Patil and Avinash Mudivedu
Last Update: 04/06/2017
Description: 
Generate Certificate Signing Request, OpenSSL CA signed, or Microsoft CA signed for 
all the VVD target hosts.
.....
NOTE: Code base of certgen.sh by CSE Reference Architecture Team.
Original cergen.sh located on http://kb.vmware.com/kb/2107816.
NOTE: Required Microsoft CA to have Web Server template as specified in KB 2062108 (vSphere 5.x) And
KB 2112009 (vSphere 6.0)

The requirements for the execution of this script are:
1. Windows 2008 or higher
2. Java 1.7++ SDK
3. Openssl 1.0.2d or higher
4. Run on computer that is part of the domain where Microsoft Certification Authority and Certification
Authority Web Enrollment reside.
5. (Optional) To run on computer not part of the domain, another Windows 2008 or higher server must 
deployed Certificate Enrollment Web Service and Certificate Enrollment Policy Web Service.

Q&A:
1. If you get an error '..execution of scripts is diabled on this system.' while executing scripts, 
then run the following command in Powershell before running script.
> Execute Get-ExecutionPolicy
If returned 'Restricted', then execute 'Set-ExecutionPolicy RemoteSigned'

2. If you get 'permissionDenied' error during execution, resolve issue
by launching PowerShell Windows with Administrator account.
#>

###################################################################################################
#
# Global variables
#
###################################################################################################

param(
	[Parameter(Mandatory=$false,ParameterSetName="help")]
		[Alias("h")][switch]$help = $false,
	[Parameter(Mandatory=$false,ParameterSetName="validate")]
		[Alias("v")][switch]$validate = $false,
	[Parameter(Mandatory=$true,ParameterSetName="self")]
		[Alias("openssl","open","o")][switch]$OpenSSLCASigned = $false,
	[Parameter(Mandatory=$true,ParameterSetName="MSCA")]
		[Alias("ca")][switch]$MSCASigned = $false,
	[Parameter(Mandatory=$true,ParameterSetName="csr")]
		[switch]$CSR = $false,
	[Parameter(Mandatory=$false,ParameterSetName="csr")]
		[Alias("e")][switch]$extra = $false,		
    [Parameter(Position=0,Mandatory=$false,ParameterSetName="MSCA")]
		[Alias("a")][string]$attrib,
    [Parameter(Position=1,Mandatory=$false,ParameterSetName="MSCA")]
		[Alias("c")][string]$config,
    [Parameter(Position=2,Mandatory=$false,ParameterSetName="MSCA")]
		[Alias("user","name","u")][string]$username,
    [Parameter(Position=3,Mandatory=$false,ParameterSetName="MSCA")]
		[Alias("pass","pw","p")][string]$password,
	[Parameter(Position=4,Mandatory=$false,ParameterSetName="MSCA")]
		[Alias("int")][switch]$intermediate,
    [Parameter(Mandatory=$false,ParameterSetName="all")]
		[switch]$all = $false		
)

$CURDIR = get-location
$SUB_ALT_NAMES=""
$DOMAIN=""
$CONTINUE="y"
$COMMON=""
$ConfigFilesDir=""
$INPUT="[CERT]"
$HOSTS="SAN"
$TARGETCOUNT=0
$CSRDir="CSRCerts"
$SignedByMSCADir="SignedByMSCACerts" 
$SignedByOpenSSLCADir="SignedByOpenSSLCerts"
$CERTDIR=""
$Root64=""
$p12Password=""
$caConfig=""
$caAttrib=""
$caUserName=""
$caPassword=""
$myCertList=New-Object System.Collections.Generic.List[System.String]

###################################################################################################
#
# Display help 
#
###################################################################################################
Function get-help {
	.\CertgenVVD.ps1 = split-path $MyInvocation.ScriptName -leaf
	Write-Host
	Write-Host "##################################################################################"
	Write-Host ""
	Write-Host "> .\CertgenVVD.ps1 -OpenSSLCASigned|-MSCASigned[attrib,config,username,password,intermediate]|-CSR"
	Write-Host "`t-OpenSSLCASigned|OpenSSL	Signed with generated OpenSSL ROOT CA"
	Write-Host "`t-MSCASigned|ca -attribute ATTR -config CONFIG -username USER -password PASSWD"
	Write-Host "`t`t	Signed with Microsoft ROOT CA"
	Write-Host "`t-CSR	Generate only CSR file for third party to sign"
	Write-Host "`t-CSR -extra	Generate different cert format after 3rd party signed cert."
	Write-Host "`t-all Generate all CSR, OepSSLCASigned, and Microsoft CA signed."	
	Write-Host "`t-help|h	Display help"
	Write-Host "`t-validate|v	Validate system readiness"
	Write-Host ""
	Write-Host "Example: Generate only certificate service request and signed by 3rd party."
	Write-Host "`t.\CertgenVVD.ps1 -CSR"	
	Write-Host ""
	Write-Host "Example: Generate different cert format after 3rd party signed cert."
	Write-Host "`t.\CertgenVVD.ps1 -CSR -extra"
	Write-Host ""
	Write-Host "Example: Generate and signed by OpenSSL Root CA certificates."
	Write-Host "`t.\CertgenVVD.ps1 -openSSL|OpenSSLCASigned"
	Write-Host ""
	Write-Host "Example: Generate and signed by Microsoft Certificate Authority (CA) certificates."
	Write-Host "`tNOTE: Use '$scriptName -validate' to retrieve -attrib and -config"
	Write-Host "`t.\CertgenVVD.ps1 -MSCASigned -attrib 'CertificateTemplate:vSphere6.0' "
	Write-Host ""
	Write-Host "`t`t-config '10.153.158.21\rainpole-rpad01-CA' -username Rainpole\Administrator -password VMware1!"
	Write-Host ""
	Write-Host "`t`t-attrib	Certificate Template for vSphere 6.0 (KB 2112009)"
	Write-Host "`t`t-config		Certificate Authority (CA) URL and CA Name (lookup with certutil.exe)"
	Write-Host "`t`t-username|user	(Optional)User with access to Certificate Authority web enrollment"
	Write-Host "`t`t-password|pass	(Optional)User password"
	Write-Host ""
	Write-Host "Example: Generate all CSR, OepSSLCASigned, and Microsoft CA signed."
	Write-Host "`t.\CertgenVVD.ps1 -all"
	Write-Host ""
	Write-Host "##################################################################################"
	Write-Host 
	exit
}

###################################################################################################
#
# The requirements for the execution of this script are:
# 1. Windows 2008 or higher
# 2. Java 1.7++ SDK
# 3. Openssl 1.0.2d or higher
# 4. Run on computer that is part of the domain where Microsoft Certification Authority and Certification
# Authority Web Enrollment reside.
# 5. (Optional) To run on computer not part of the domain, another Windows 2008 or higher server must 
# deployed Certificate Enrollment Web Service and Certificate Enrollment Policy Web Service.
#
###################################################################################################
Function validate {

	# check keytool.exe exit and exeuctable with Path set
	# check certulti.exe reutrns CA cert
	# check certreq works from the system (check if part of domain or not)
	$comp_openssl = 0
	$comp_keytool = 0
	$comp_certutil = 0
	$cmd_openssl = openssl version 2>&1
	if ($cmd_openssl -match "^Openssl 1.0*") { 
		$comp_openssl = 1
		Write-Host "*****[INFO] Openssl 1.0 = checked.  -CSR executable"
	} else {
		Write-Host "*****[ERROR] Required Openssl 1.0++.  Please install and set path."
		exit
	}
	
	$cmd_keytool = keytool -importkeystore -help 2>&1
	if ($cmd_keytool -match "keytool -importkeystore [OPTION]*") {
		$comp_keytool = 1
		Write-Host "*****[INFO] Keytool = checked.  -CSR|-OpenSSLCASigned executable"
	} else {
		Write-Host "*****[ERROR] Required keytool.  Please install Java JDK 1.6++ and set path."
		Write-Host "*****[WARN] ONly -CSR executable will work."
	}
	
	
	if (Is-Host-In-Domain) {
		$config = get-ca-config

		if ($config -ne "none") {
			$comp_certutil = 1
			Write-Host "*****[INFO] Certificate Authority = checked.  -MSCASigned executable"
			Write-Host
			Write-Host "---------------------------------------------------------------------------" 
			Write-Host "*****[INFO] CA Config = $config"
			get-ca-dns-hostname | out-null
			get-ca-name
			get-CES-URL
			get-ca-template | out-null
			Write-Host
		} else {
			Write-Host "*****[ERROR] Host in domain but no CA found. Use CES/CEP."
		}
	} else {
		Write-Host "*****[ERROR] Current host not part of domain. Required CA CES/CEP configured."
	}
	exit
}

###################################################################################################
#
# Get Microsoft Certificate Authority Name
#	
###################################################################################################
Function get-ca-name {
	$val = certutil -adca
	#$val -match 'cn = (.+)'
	#Write-Host $Matches
	$f = ($val | Select-String -pattern 'cn = (.*)').matches[0]
	$f = $f -replace " ",""
	$CAName = ($f -split "=")[1]
	Write-Host "*****[INFO] CA Name = $CAName"
	return $CAName
}


###################################################################################################
#
# Get CES URL used by non-domain PC to access Microsoft CA
#	
###################################################################################################
Function get-CES-URL {
	$val = certutil -adca
    if (($val | Select-String -pattern 'https://.*/CES') -ne $null) {
        $CESURL = ($val | Select-String -pattern 'https://.*/CES').matches[0]
        Write-Host "*****[INFO] CA CES URL = $CESURL"
    }
	#return $CESURL	
}

###################################################################################################
#
# Return true if host is in a domain
#	
###################################################################################################
Function Is-Host-In-Domain {
	[string]$domainName = (get-WmiObject -class win32_computersystem).domain
	Write-Host "*****[INFO] Domain Name: $domainName"
	if ([string]::Compare($domainName,"WORKGROUP",$True) -eq 0) {
		$isDomain = $False
	} else {
		$isDomain = $True
	}
	return $isDomain
}

###################################################################################################
#
# Get DNS host name of CA
#	
###################################################################################################
Function get-ca-dns-hostname {
	$val = certutil -adca
	$f = ($val | Select-String -pattern 'dNSHostName = (.*)').matches[0]
	$f = $f -replace " ",""
	$CAHostName = ($f -split "=")[1]
	Write-Host "*****[INFO] CA HostName = $CAHostName"
	return $CAHostName
}

###################################################################################################
#
# Get a list of Certificate Template used by Web Enrollment from Certificate Authority
#	
###################################################################################################
Function get-ca-template {
    $val = ""
	[string]$val = certutil -adca
	$f = $val | Select-String -pattern '\d{1,2}: [\w`.]+' -allMatches

	Write-Host "*****[INFO] Following CA Template Policy available:"
	foreach ($m in $f.matches) {
		[string]$a = $m.Groups[0].ToString()
		Write-Host "*****[INFO]`t$a" 
		if (($a.ToLower()).Contains('vsphere') -or ($a.ToLower()).Contains('vmware')) {
			$a = $a -replace " ",""
			$val = ($a -split ":")[1]			
		}
	}
	
    return $val
	<#
	[string]$cmd_certutil = certutil -CATemplates -mt 2>&1
	$f = $cmd_certutil | Select-String -pattern '[\w`.-]+:' -allMatches
	$i = 1
	foreach ($m in $f.matches) {		
		if ($m -notmatch "Auto-Enroll|CertUtil") {
			#$m = $m -replace ".$"
			Write-Host "*****[INFO]`t$i. $m" 
			$i++
		}
	 }
	 #>
}

###################################################################################################
#
# Retrieve the 'config' parameters from certutil.exe output which is used to access
# Certificate Authority Web Enrollment through CLI.
#
#	Not useful if host is not a domain PC or not run from CA
#
###################################################################################################
Function get-ca-config {
	[string]$cmd_certutil = certutil -getconfig 2>&1
	if ($cmd_certutil -match '"(.+?)"') {
		$result = $Matches[1]
		write-host "*****[INFO] Found config: $result"
	} else {
		write-host "*****[WARN] Not found config parameter. Using dnsHostname\caName search."
		$dnsHostname = get-ca-dns-hostname
		$caName = get-ca-name
		$result = "$dnsHostname\$caName"
	}
	return $result
}

###################################################################################################
#
# Display a list of certificates generated
# 
###################################################################################################
Function list-certs-generated {
	Write-Host ""
    Write-Host "*****[INFO] List of Certificates generated: "
	if ($myCertList.count -lt 1) {
		Write-Host "*****`t-- none --"
	} else {
		foreach ($index in $myCertList){
			$i = $myCertList.IndexOf($index) + 1
			Write-Host "*****[INFO]`t$i. $index"
		}
	}
	Write-Host ""
}

###################################################################################################
#
# Retrieve user password to signed P12 and JKS files.  The same password will be used for all
# the VVD target hosts.
#
###################################################################################################
Function GetPassword {
	if ([string]::IsNullOrEmpty($global:p12Password)) {
		Write-Host "*****[INFO] Entered keystore password for P12/PEM certificates. (Must be 7 characters long.)"
		[string]$PASS = Read-Host -Prompt "Enter password"
		[string]$PASS_CONFIRM = Read-Host -Prompt "Confirm password"

		If (!($PASS -ceq $PASS_CONFIRM) -or ($PASS.length -le 6))  {
			Write-Host
			Write-Host "***** [ERROR] Passwords don't match or equal or greater than 7 char ...try again"
			Write-Host
			GetPassword
		}
		
		Write-Host "*****[INFO] P12 Password assigned: $PASS_CONFIRM"
		$global:p12Password = $PASS

	}
	
}

###################################################################################################
#
# Retrieve all folders in $CSRDIR and find *.cer and *.key 
#
###################################################################################################		
function create-extra-certs-csrdir () {
	$global:Root64="$CERTDIR/RootCA"

	GetPassword
	# retrieve each folder and generate addition cert format
	foreach ($item in Get-ChildItem $CERTDIR -exclude "RootCA" | where {($_.psiscontainer)}) {
		$NAME = split-path $item -leaf
		#Write-Host $NAME
		complete_certs 
	}
	
	list-certs-generated
}

###################################################################################################
#
# Create VRA specific keystore for AppD such as server.xml, JKS for VCO (jssecacerts), JKS for AppD
#
###################################################################################################
Function create_vra_appd {
#Create server.xml for AppD
	$contents = '
<?xml version="1.0"?>
<Server port="${base.shutdown.port}"
        shutdown="SHUTDOWN">
    <Listener className="org.apache.catalina.core.JasperListener"/>
    <Listener className="org.apache.catalina.core.JreMemoryLeakPreventionListener"/>
    <Listener className="org.apache.catalina.mbeans.GlobalResourcesLifecycleListener"/>
    <Listener className="com.springsource.tcserver.licensing.LicensingLifecycleListener"/>
    <Listener className="com.springsource.tcserver.serviceability.deploy.TcContainerDeployer"/>
    <Listener accessFile="${catalina.base}/conf/jmxremote.access"
              authenticate="true"
              bind="127.0.0.1"
              className="com.springsource.tcserver.serviceability.rmi.JmxSocketListener"
              passwordFile="${catalina.base}/conf/jmxremote.password"
              port="${base.jmx.port}"
              useSSL="false"/>
    <Service name="Catalina">
        <Executor maxThreads="300"
                  minSpareThreads="50"
                  name="tomcatThreadPool"
                  namePrefix="tomcat-http--"/>
        <Engine defaultHost="localhost"
                name="Catalina">
            <Host appBase="webapps"
                  autoDeploy="true"
                  deployOnStartup="true"
                  deployXML="true"
                  name="localhost"
                  unpackWARs="true">
                <Valve className="org.apache.catalina.valves.AccessLogValve"
                       directory="logs"
                       pattern="%h %l %u %t &quot;%r&quot; %s %b"
                       prefix="localhost_access_log."
                       suffix=".txt"/>
            </Host>
        </Engine>
        <Connector acceptCount="100"
                   connectionTimeout="20000"
                   executor="tomcatThreadPool"
                   maxKeepAliveRequests="15"
                   port="${bio.http.port}"
                   protocol="org.apache.coyote.http11.Http11Protocol"
                   redirectPort="${bio.https.port}"/>
        <!-- cipher suite list is from VMware PSP 3.3 recommended list -->
        <Connector port="8443" protocol="HTTP/1.1" SSLEnabled="true" socket.soKeepAlive="true"
                   maxThreads="150" scheme="https" secure="true"
                   clientAuth="want" sslProtocol="TLS"
                   keystoreFile="/home/darwin/keystore/appd.jks"
                   keystorePass="D@rw!n_Server"
                   truststoreFile="/home/darwin/keystore/appd.truststore"
                   truststorePass=""
                   URIEncoding="UTF-8"
                   compression="on" compressionMinSize="2048" noCompressionUserAgents="gozilla, traviata"
                   compressableMimeType="application/json-type,text/html,text/xml,text/css,text/plain,image/gif,image/png,application/javascript,application/x-font-woff"
                   server="Apache"
                   ciphers="TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                   TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                   TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
                   TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
                   TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                   TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
                   TLS_DH_RSA_WITH_AES_256_CBC_SHA,
                   TLS_DH_DSS_WITH_AES_256_CBC_SHA,
                   TLS_RSA_WITH_AES_256_CBC_SHA,
                   TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   TLS_RSA_WITH_AES_128_CBC_SHA,
                   TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
                   TLS_DH_RSA_WITH_AES_128_CBC_SHA,
                   TLS_DH_DSS_WITH_AES_128_CBC_SHA"/>
        	 <Connector port="8444" protocol="HTTP/1.1" SSLEnabled="true" socket.soKeepAlive="true"
		maxThreads="150" scheme="https" secure="true"
		sslProtocol="TLS"
		keystoreFile="/home/darwin/keystore/appdui.jks"
		keystorePass="'+$global:p12Password+'"
		keyPass ="'+$global:p12Password+'"
		URIEncoding="UTF-8"
		compression="on" compressionMinSize="2048" noCompressionUserAgents="gozilla, traviata"
		compressableMimeType="application/json-type,text/html,text/xml,text/css,text/plain,image/gif,image/png,application/javascript,application/x-font-woff"
		server="Apache"
		ciphers="TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
		TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
		TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
		TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
		TLS_DH_RSA_WITH_AES_256_CBC_SHA,
		TLS_DH_DSS_WITH_AES_256_CBC_SHA,
		TLS_RSA_WITH_AES_256_CBC_SHA,
		TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
		TLS_RSA_WITH_AES_128_CBC_SHA,
		TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
		TLS_DH_RSA_WITH_AES_128_CBC_SHA,
		TLS_DH_DSS_WITH_AES_128_CBC_SHA"/>
    </Service>
    <Listener className="org.apache.catalina.core.ThreadLocalLeakPreventionListener"/>
</Server>
'

	Write-Host "*****[INFO] Creating 'server.xml' file"
	New-Item $CERTDIR/$NAME/server.xml -type file -value $contents
	
	#Create JKS for vCO
    keytool -importkeystore -deststorepass dunesdunes -destkeystore $CERTDIR/$NAME/jssecacerts `
		-srckeystore $CERTDIR/$NAME/$NAME.4.p12 -srcstoretype PKCS12 -srcstorepass "$global:p12Password" `
		-srcalias $NAME -destalias dunes -deststoretype JKS -noprompt >> $LOGFILE 2>&1

    #Embedded vCO on vCAC VA requires private key pass to be the same as keystore so change it here
    keytool -keypasswd -alias dunes -new dunesdunes -keystore $CERTDIR/$NAME/jssecacerts `
		-storepass dunesdunes -keypass $global:p12Password >> $LOGFILE 2>&1

    #Create JKS for AppD
    keytool -importkeystore -deststorepass $global:p12Password -destkeystore $CERTDIR/$NAME/appdui.jks `
		-srckeystore $CERTDIR/$NAME/$NAME.4.p12 -srcstoretype PKCS12 -srcstorepass $global:p12Password `
		-destalias ssl -alias $NAME -deststoretype JKS >> $LOGFILE 2>&1
}

###################################################################################################
#
# For all the VVD target hosts that have CRT and ROOT CA available, this function generate different
# certificate format for different different solution requirements.
# Following file formats are available:
#	1. P12 password protected file (eg. server.p12)
#	2. PEM without private key (eg. server.pem)
#	3. JKS for vCO (eg. jssecacerts ) ??
#	4. JKS for AppdD (eg. appdui.jks) ??
#	5. PEM with private key (eg. server-full.pem)
#	
###################################################################################################
Function complete_certs {
    
    If (!( Test-Path $CERTDIR/$NAME/$NAME.1.cer )){
        Write-Host "*****[WARN] Could not find $CERTDIR/$NAME/$NAME.1.cer. SKIP."
        #Write-Host
        #exit 1
		return
    }
    
    #Convert from DER to PEM if needed
    #openssl x509 -in $CERTDIR/$arg2/$arg2.cer -inform der -out $CERTDIR/$arg2/$arg2.cer >> $LOGFILE 2>&1
      
    If (!( Test-Path $global:Root64/Root64.cer )){
        Write-Host ERROR: Could not find $global:Root64/Root64.cer
        Write-Host
        exit 1
    }
    
    #Convert from DER to PEM if needed
    openssl x509 -in $MSCERT/Root64.cer -inform der -out $MSCERT/Root64.cer >> $LOGFILE 2>&1
    
    #Create P12
	Write-Host "*****[INFO] Creating P12 file password."
    openssl pkcs12 -export -in $CERTDIR/$NAME/$NAME.1.cer -inkey $CERTDIR/$NAME/$NAME.key `
		-certfile $global:Root64/Root64.cer -name $NAME -passout pass:$global:p12Password `
		-out $CERTDIR/$NAME/$NAME.4.p12 >> $LOGFILE 2>&1
		
    If (!( Test-Path $CERTDIR/$NAME/$NAME.4.p12 )) {
        Write-Host "ERROR: Could not generate P12 file $NAME.4.p12"
        Write-Host
        Get-Content $LOGFILE
    }

    #Create P12 without RootCA cert
	Write-Host "*****[INFO] Creating P12 without RootCA file password."
    openssl pkcs12 -export -in $CERTDIR/$NAME/$NAME.1.cer -inkey $CERTDIR/$NAME/$NAME.key `
	    -name $NAME -passout pass:$global:p12Password `
		-out $CERTDIR/$NAME/$NAME.5.p12 >> $LOGFILE 2>&1
    #Create PEM without private key
	
	
	if ($intermediate) {
		Get-Content $CERTDIR/$NAME/$NAME.1.cer | set-content $CERTDIR/$NAME/$NAME.3.pem
		Get-Content $global:Root64/Root64.cer | add-content $CERTDIR/$NAME/$NAME.3.pem
	} else {
		Write-Host "*****[INFO] Creating PEM without private key."
		openssl pkcs12 -nokeys -in $CERTDIR/$NAME/$NAME.4.p12 -inkey $CERTDIR/$NAME/$NAME.key `
			-out $CERTDIR/$NAME/$NAME.3.pem -nodes -passin pass:$global:p12Password >> $LOGFILE 2>&1
	}

		#Create PEM and ROOT with private key
		Write-Host "*****[INFO] Creating PEM , ROOT, and private key."
		Get-Content $CERTDIR/$NAME/$NAME.1.cer | set-content $CERTDIR/$NAME/$NAME.2.chain.pem
		Get-Content $global:Root64/Root64.cer | add-content $CERTDIR/$NAME/$NAME.2.chain.pem
		Get-Content $CERTDIR/$NAME/$NAME.key | add-content $CERTDIR/$NAME/$NAME.2.chain.pem
	
	
	
	
	#Create .p7b
	Write-Host "**** [INFO] Creating .P7b"
	
	 openssl crl2pkcs7 -nocrl -certfile $CERTDIR/$NAME/$NAME.1.cer -certfile $global:Root64/Root64.cer -inform der -out $CERTDIR/$NAME/$NAME.6.p7b
	 
	  if(($name.ToLower()).Contains('vdp')){
			 Write-Host "****  creating .p7b for vdp "
			  certreq.exe -submit -attrib $global:caAttrib -config $global:caConfig `
					-UserName $global:caUserName -p changeit `
					$CERTDIR/$NAME/$NAME.1.csr $CERTDIR/$NAME/$NAME.3.cer $CERTDIR/$NAME/$NAME.7.p7b
			Write-Host "****  importing .P7b to .keystore"		
	     keytool -import -alias tomcat -keystore $CERTDIR/$NAME/.keystore -file $CERTDIR/$NAME/$NAME.7.p7b -storepass changeit -noprompt
	 }
	 
	 
	if (($NAME.ToLower()).Contains('vra') ) {
		# create server.xml file for App Web Service
		create_vra_appd
		
		# write readme file
		Add-Content $CERTDIR/$NAME/readme.txt "$Name.key`t`tPrivate Key"
		Add-Content $CERTDIR/$NAME/readme.txt "$Name.1.cer`t`tBase 64 encoded. Certificate only."
		Add-Content $CERTDIR/$NAME/readme.txt "$Name.2.chain.pem`t`tBase 64 encoded.  Private key, cert, and Root cert."
		Add-Content $CERTDIR/$NAME/readme.txt "$Name.3.pem`t`tBase 64 encoded. Certificate and Root cert without private key."
		Add-Content $CERTDIR/$NAME/readme.txt "$Name.4.p12`t`tP12 format. Private key, cert, and Root cert with encryption."
		Add-Content $CERTDIR/$NAME/readme.txt "$NAME.5.p12`t`tP12 format. Private key, cert with encryption."
		Add-Content $CERTDIR/$NAME/readme.txt "$NAME.6.p7b`t`tP7b format.cert and Root cert."
		Add-Content $CERTDIR/$NAME/readme.txt "appdui.jks`t`tJKS for vRealize Automation Application ONLY."
		Add-Content $CERTDIR/$NAME/readme.txt "server.xml`t`tServer file for vRealize Automation Application ONLY."
		Add-Content $CERTDIR/$NAME/readme.txt "jssecacerts`t`tJKS format for vRealize Orchestrator ONLY"
		Add-Content $CERTDIR/$NAME/readme.txt "`r`t"
		Add-Content $CERTDIR/$NAME/readme.txt "vRLI, vROps`t`tUsed *.2.chain.pem certificate for replacement"
		Add-Content $CERTDIR/$NAME/readme.txt "PSC, vCenter`t`tUsed *.key and *.1.cer certificate for replacement"
		Add-Content $CERTDIR/$NAME/readme.txt "SRM, VRM `t`tUsed *.4.p12 certificate for replacement"
		Add-Content $CERTDIR/$NAME/readme.txt "NSX Manager`t`tUsed *.5.p12 certificate for replacement"
		Add-Content $CERTDIR/$NAME/readme.txt "Other`t`tUsed *.key and *.1.cer certificate for replacement"
		Add-Content $CERTDIR/$NAME/readme.txt "`r`t"    
		Add-Content $CERTDIR/$NAME/readme.txt "P12 keystore password: $global:p12Password"
	} else {
		# write readme file
		Add-Content $CERTDIR/$NAME/readme.txt "$Name.key`t`tPrivate Key"
		Add-Content $CERTDIR/$NAME/readme.txt "$Name.1.cer`t`tBase 64 encoded. Certificate only."
		Add-Content $CERTDIR/$NAME/readme.txt "$Name.2.chain.pem`t`tBase 64 encoded.  Private key, cert, and Root cert."
		Add-Content $CERTDIR/$NAME/readme.txt "$Name.3.pem`t`tBase 64 encoded. Certificate and Root cert without private key."
		Add-Content $CERTDIR/$NAME/readme.txt "$Name.4.p12`t`tP12 format. Private key, cert, and Root cert with encryption."
		Add-Content $CERTDIR/$NAME/readme.txt "$NAME.5.p12`t`tP12 format. Private key, cert with encryption."
		Add-Content $CERTDIR/$NAME/readme.txt "$NAME.6.p7b`t`tP7b format.cert and Root cert."
		Add-Content $CERTDIR/$NAME/readme.txt "`r`t"
		Add-Content $CERTDIR/$NAME/readme.txt "vRLI, vROps`t`tUsed *.2.chain.pem certificate for replacement"
		Add-Content $CERTDIR/$NAME/readme.txt "PSC, vCenter`t`tUsed *.key and *.1.cer certificate for replacement"
		Add-Content $CERTDIR/$NAME/readme.txt "SRM, VRM `t`tUsed *.4.p12 certificate for replacement"
		Add-Content $CERTDIR/$NAME/readme.txt "NSX Manager`t`tUsed *.5.p12 certificate for replacement"
		Add-Content $CERTDIR/$NAME/readme.txt "Other`t`tUsed *.key and *.1.cer certificate for replacement"
		Add-Content $CERTDIR/$NAME/readme.txt "`r`t"    
		Add-Content $CERTDIR/$NAME/readme.txt "P12 keystore password: $global:p12Password"
	}
	
	$myCertList.Add("$NAME for $CERTDIR")
    Write-Host "*****[INFO] Certificate Generation Complete *****"
	
    <#
	Write-Host "Certificates generated for servers:"
	if ([string]::IsNullorEmpty($ConfigFilesDir)) {
		$ConfigFilesDir = "ConfigFiles"
	}
    Get-Content $CURDIR/$ConfigFilesDir/$NAME.txt
    Write-Host
    Write-Host
   
    Write-Host
    Write-Host "**Finished**"
	#>
}

###################################################################################################
#
# Generate CSR for all VVD target hosts.  
# @param:
#	$arg1	Name of folder containing all input files.  The input file contains attributes used	
#			to generate the config file to subsequently generate CSR.
#
###################################################################################################
Function create_all_VVD_CRT([string]$arg1) {
	$ConfigFilesDir = $arg1
	
	$files = Get-ChildItem $CURDIR\$ConfigFilesDir -filter "*.txt" 
	#Write-Host "*****[INFO] Found files: $files"

	ForEach ($file in $files){
    
        Write-Host
        Write-Host "================== Starting $file ============================="
		$NAME = $file.basename
		# handle case where config file don't have CN defined: used default CN+$NAME for uniqueness
		$CN=$DefaultCN+"_"+$NAME
		$COUNT=0;
		$LINESCOUNT=0
		$content = Get-Content $CURDIR\$ConfigFilesDir\$file 
		foreach ($line in $content){
			switch -wildcard ($line) {
				"NAME=*" {
							$LINESCOUNT++
							$rear = ($line -split ',*=')[1]
							IF ($rear -ne "default"){
								$NAME=$rear
							}
						 }
				"ORG=*" {
							$LINESCOUNT++
							$rear = ($line -split ',*=')[1]
							IF ($rear -ne "default"){
								$ORG=$rear
							}
						 }
				"OU=*" {
							$LINESCOUNT++
							$rear = ($line -split ',*=')[1]
							IF ($rear -ne "default"){
								$OU=$rear
							}
						 }
				"LOC=*" {
							$LINESCOUNT++
							$rear = ($line -split ',*=')[1]
							IF ($rear -ne "default"){
								$LOCALITY=$rear
							}
						 }
				"ST=*" {
							$LINESCOUNT++
							$rear = ($line -split ',*=')[1]
							IF ($rear -ne "default"){
								$STATE=$rear
							}
						 }
				"CC=*" {
							$LINESCOUNT++
							$rear = ($line -split ',*=')[1]
							IF ($rear -ne "default"){
								$COUNTRY=$rear
							}
					   }
                "CN=*" {
							$LINESCOUNT++
							$rear = ($line -split ',*=')[1]
							IF ($rear -ne "default"){
								$CN=$rear
							}
                            ELSE {
                                $CN=$DefaultCN+"_"+$NAME
                            }                            
					   }
                 "keysize=*" {
                            $LINESCOUNT++
							$rear = ($line -split ',*=')[1]
							IF ($rear -ne "default"){
								$keysize=$rear
							}
                        }
			 "*$HOSTS*" { 
							$LINESCOUNT++
							$TARGETCOUNT=$LINESCOUNT
					   } 
					"" {
							$LINESCOUNT++
					   }   
			   default {
							$LINESCOUNT++					
					   }
					   
			} 
		}
		
		#Write-Host $LINESCOUNT,$TARGETCOUNT
		
		IF (Test-Path $CERTDIR){
			New-Item -Force -ItemType directory -Path $CERTDIR/$NAME 
		}
		
		$LOGFILE="$CERTDIR/$NAME/$NAME.log"
		
	#Create configuration file for CSR    
	$content = '[ req ]
default_bits = '+$keysize+'
default_keyfile = ' +$NAME+ '.key
distinguished_name = req_distinguished_name
encrypt_key = no
prompt = no
string_mask = nombstr
req_extensions = v3_req

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment, dataEncipherment, nonRepudiation
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alternate_names

[ req_distinguished_name ]
countryName = '+$COUNTRY+'
stateOrProvinceName = '+$STATE+'
localityName = '+$LOCALITY+'
0.organizationName = '+$ORG+'
organizationalUnitName = '+$OU+'
commonName = '+$CN+'

[ alternate_names ]
'
		Write-Host "*****[INFO] Creating '$NAME' config file"
		New-Item $CERTDIR/$NAME/config.cfg -type file -value $content
		
		#Add servers to config.cfg
		$i=0
        $j=0
		
		$HOSTDETAILS = (Get-Content $CURDIR\$ConfigFilesDir\$file)[$TARGETCOUNT..$LINESCOUNT]
		foreach ($line in $HOSTDETAILS){
			IF(($line -ne "") -And ($line -notlike '#*')) {
                IF($line -as [ipaddress]) {
                   
                        $j++
                        Add-Content $CERTDIR/$NAME/config.cfg "IP.$j = $line"
				    
                }
                ELSE {
    				IF (($line -like '*.*') -Or ($DOMAIN -eq "")) {
                        $i++
                        Add-Content $CERTDIR/$NAME/config.cfg "DNS.$i = $line"
				    }
				    ELSE {
					   $i++
					   Add-Content $CERTDIR/$NAME/config.cfg "DNS.$i = $line.$DOMAIN"
				    }
                }
			}
		}

		# Create a private key and CSR for Self-Signed Root CA
		Write-Host "*****[INFO] Create '$NAME' private key and CSR files."
		if (Test-Path $CERTDIR/$NAME/$NAME-orig.key) {
			openssl req -new -sha256 -nodes -out $CERTDIR/$NAME/$NAME.csr `
				-key $CERTDIR/$NAME/$NAME-orig.key -config $CERTDIR/$NAME/config.cfg >> $LOGFILE 2>&1	
			Write-Host "*****[WARN]`tRe-using existing private-key, $NAME.key, successful!"
			Write-Host "*****[INFO]`tCreating new CSR file, $NAME.csr, successful."
		} else {
	         if(($name.ToLower()).Contains('vdp')){
			     keytool -genkeypair -noprompt -v -alias tomcat -keyalg RSA -sigalg SHA256withRSA -keystore $CERTDIR/$NAME/.keystore -storepass changeit -keypass changeit -validity 3650 -dname "CN=$CN, OU=$OU, O=$ORG, L=$LOCALITY, S=$STATE, C=$COUNTRY"
			  #mgmt01vdp01.sfo01
			     keytool -certreq -noprompt -alias tomcat -keyalg RSA -file $CERTDIR/$NAME/$NAME.1.csr -keystore $CERTDIR/$NAME/.keystore -storepass changeit
			   }
				 openssl req -new -sha256 -nodes -out $CERTDIR/$NAME/$NAME.csr `
				 -keyout $CERTDIR/$NAME/$NAME-orig.key `
				 -config $CERTDIR/$NAME/config.cfg >> $LOGFILE 2>&1
				 Write-Host "*****[INFO]`tCreating new private-key, $NAME.key, successful!"
				 Write-Host "*****[INFO]`tCreating new CSR file, $NAME.csr, successful."
		}		
		
		 #Convert private key to RSA format
		
		 openssl rsa -in $CERTDIR/$NAME/$NAME-orig.key -out $CERTDIR/$NAME/$NAME.key >> $LOGFILE 2>&1

		#
		# Signed certificate using OpenSSL CA or Microsoft CA	
		# - CSR = skip this steps
		# - OpenSSLCASigned = Signed certifate with Self-Signed Root CA
		# - MSCASigned = Signed certificate with Microsoft CA
		#
		#Get-Content $CERTDIR/$NAME/$NAME.csr
		IF (!$CSR) {
			IF($OpenSSLCASigned){
				openssl x509 -req -days 3650 -in $CERTDIR/$NAME/$NAME.csr `
					-CA $CERTDIR/RootCA/Root64.cer -CAkey $CERTDIR/RootCA/Root64.key `
					-out $CERTDIR/$NAME/$NAME.1.cer `
					-extensions v3_req `
					-CAserial  $CERTDIR/RootCA/serial `
					-extfile $CERTDIR/$NAME/config.cfg >> $LOGFILE 2>&1
				$global:Root64="$CERTDIR/RootCA"
				Write-Host "*****[INFO]`tSigning certificate, $NAME.1.cer, successful."
			}
			
			if ($MSCASigned){
			     if(($name.ToLower()).Contains('vdp')){
				     certreq.exe -submit -attrib $global:caAttrib -config $global:caConfig `
					 -UserName $global:caUserName -p changeit `
					 $CERTDIR/$NAME/$NAME.1.csr $CERTDIR/$NAME/$NAME.2.cer >> $LOGFILE 2>&1 
				 }
				 
				 certreq.exe -submit -attrib $global:caAttrib -config $global:caConfig `
					-UserName $global:caUserName -p $global:caPassword `
					$CERTDIR/$NAME/$NAME.csr $CERTDIR/$NAME/$NAME.1.cer >> $LOGFILE 2>&1 
				$global:Root64="$CERTDIR/RootCA"
				Write-Host "*****[INFO]`tSigning certificate, $NAME.1.cer, successful."
			}
						
			Write-Host "*****[INFO] Initiate complete certificates creation."
			complete_certs 2>&1
		} Else {
			$myCertList.Add("$NAME for $CERTDIR")
			continue
		}
	}
}

###################################################################################################
#
# Create Config file specifically for rootca.csr and generating Self-Signed root CA.
#	
###################################################################################################
Function get_Certificate_Root_CA {
	If(!(Test-Path $CERTDIR/RootCA)){
		mkdir $CERTDIR/RootCA
	}
	
	If(!(Test-Path $CERTDIR/RootCA/Root64-der.der) -Or (Test-Path $CERTDIR/RootCA/Root64.cer)){
		if ($intermediate) {
			certutil -config $global:caConfig -'ca.chain' $CERTDIR/RootCA/CertificateChain.p7b
			openssl pkcs7 -print_certs -inform DER -outform PEM -in $CERTDIR/RootCA/CertificateChain.p7b -out $CERTDIR/RootCA/Root64.cer
			openssl pkcs7 -print_certs -inform DER -outform PEM -in $CERTDIR/RootCA/CertificateChain.p7b -out $CERTDIR/RootCA/chainRoot64.cer
		} else {
			certutil -config $global:caConfig -'ca.cert' $CERTDIR/RootCA/Root64-der.der
			openssl x509 -inform der -in $CERTDIR/RootCA/Root64-der.der -out $CERTDIR/RootCA/Root64.cer
		}
		Write-Host "*****[INFO] Retrieve Microsoft Certificate Root CA, Root64.cer, successful."
	} else {
		Write-Host "*****[INFO] Re-use existing Microsoft Certificate Root CA, Root64.cer."
	}
	
}

###################################################################################################
#
# Create Config file specifically for root64.csr and generating Self-Signed root CA.
#	
###################################################################################################
Function create_Self_Signed_Root_CA {

	# generate the config file for Self-Signed Root CA
	$rootConfig = '[ req ]
default_bits = '+$keysize+'
default_keyfile = Root64.key
distinguished_name = req_distinguished_name
encrypt_key = no
prompt = no
string_mask = nombstr
req_extensions = v3_req

[ ca ]
default_ca	= CA_default		# The default ca section
[ CA_default ]

dir		= '+$CERTDIR+'		# Where everything is kept
certs		= $dir/RootCA	# Where the issued certs are kept
crl_dir		= $dir/RootCA		# Where the issued crl are kept
database	= $dir/RootCA/index.txt	# database index file.
new_certs_dir	= $dir/RootCA		# default place for new certs.
default_md	= default		# use public key default MD
serial		= $dir/RootCA/serial 		# The current serial number
policy		= policy_match

# For the CA policy
[ policy_match ]
countryName		= match
stateOrProvinceName	= match
organizationName	= match
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment, dataEncipherment, nonRepudiation
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alternate_names

[ req_distinguished_name ]
countryName = US
stateOrProvinceName = CA
localityName = PA
0.organizationName = Rainpole
organizationalUnitName = VVD
commonName = VMware_VVD-OpenSSL_Root_CA

[ alternate_names ]
DNS.1 = RootCA
DNS.2 = RootCA.rainpole.local

[ v3_ca ]
# Extensions for a typical CA
# PKIX recommendation.
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
# This is what PKIX recommends but some broken software chokes on critical
# extensions.
#basicConstraints = critical,CA:true
# So we do this instead.
basicConstraints = CA:true'

	New-Item $CERTDIR/RootCA/config.cfg -type file -value $rootConfig
	New-Item $CERTDIR/RootCA/index.txt -type file 
	
	
	# Create a private key and CSR for Self-Signed Root CA
	Write-Host "*****[INFO] Create Self-Signed Root CA private key and CRT files."
	$NAME = "Root64"
	
	# generate Self-Signed Root private key
	openssl req -new -sha256 -newkey rsa:$keysize -keyout $CERTDIR/RootCA/$NAME.key `
		-out $CERTDIR/RootCA/$NAME.csr -config $CERTDIR/RootCA/config.cfg >> $LOGFILE 2>&1
	Write-Host "*****[INFO]`tCreating Self-Signed Root CA private key, $NAME.key, successful."
	
	# Use private key to signed itself
	openssl ca -create_serial -out $CERTDIR/RootCA/$NAME.cer -days 3650 `
		-keyfile $CERTDIR/RootCA/$NAME.key `
		-selfsign -extensions v3_ca -config $CERTDIR/RootCA/config.cfg `
		-batch `
		-infiles $CERTDIR/RootCA/$NAME.csr >> $LOGFILE 2>&1
	Write-Host "*****[INFO]`tCreating Self-Signed Root CA certificate, $NAME.cer, successful."
}

#==================================================================================================
clear-host

# display help
if ($help) { get-help }

# validate system readiness with all pre-requisites
if ($validate) { validate }

Write-Host
Write-Host "********************************************************"
Write-Host "*      VMware VVD - Signed Certificate Tool            *"
Write-Host "********************************************************"
Write-Host

Write-Host
Write-Host "This script output certificates used by VMware products in VVD stack."
Write-Host "`t1. Generate ONLY certificate signing requests(CSRs) which can be sent to any CA to sign."
Write-Host "`t2. Generate certificate signed by internal OpenSSL Certificate Authority (CA)."
Write-Host "`t3. Generate certificate signed by internal Microsoft Certificate Authority (CA)."
Write-Host

# Handle special case where CSR has signed SRT and Root CA returned from 3rd Party.
# This generate different CERT format required by different VVD solutions
if ($CSR -and $EXTRA){
	$CERTDIR = $CSRDir
	create-extra-certs-csrdir
	exit
}


#exit

$ORG=""
$OU=""
$LOCALITY=""
$STATE=""
$COUNTRY=""
$NAME=""
$DefaultCN=""
$CN=""
$keysize=2048

If (Test-Path $CURDIR/default.txt){
    Write-Host
    Write-Host "*****[INFO] Found default config file with the following attributes:"
    Get-Content $CURDIR/default.txt 
    $content =  Get-Content $CURDIR/default.txt
    foreach ($line in $content){
        $front = ($line -split ',*=')[0]
        $rear = ($line -split ',*=')[1]
        switch ($front) {
            "ORG" {$ORG=$rear}
            "OU" {$OU=$rear}
            "LOC" {$LOCALITY=$rear}
            "ST" {$STATE=$rear}
            "CC" {$COUNTRY=$rear}
            "CN" {$DefaultCN=$rear}
            "keysize" {$keysize=$rear}
            default {Write-Host "ERROR"}
        }
    }
}
Else{
    Write-Host "*****[INFO] No default file exists: using default value."
	$ORG="Rainpole"
	$OU="VVD"
	$LOCALITY="PA"
	$STATE="CA"
	$COUNTRY="US"
	$DefaultCN="VMware_VVD"
    $keysize=2048
    #exit  
}

IF ($OpenSSLCASigned -or $all){
    # generate all three, OpenSSL, CA and CSR certificates.
    if ($all) {
        $OpenSSLCASigned = $true
        $MSCASigned = $false
        $CSR = $false
    }
    
    IF (Test-Path $SignedByOpenSSLCADir){
        Remove-Item $SignedByOpenSSLCADir -Recurse -Force
    }
	New-Item -Force -ItemType directory -Path $SignedByOpenSSLCADir
    $CERTDIR = $SignedByOpenSSLCADir
	
	# Create Self-Signed Root CA directory, create config, private key, and CSR files
	New-Item -Force -ItemType directory -Path $SignedByOpenSSLCADir/RootCA
    create_Self_Signed_Root_CA
	
	# Create private key, and CSR files for all VVD target hosts using pre-existing config files 
	GetPassword
	create_all_VVD_CRT ("ConfigFiles")

	list-certs-generated
}

IF ($MSCASigned -or $all){
    # generate all three, OpenSSL, CA and CSR certificates.
    if ($all) {
        $OpenSSLCASigned = $false
        $MSCASigned = $true
        $CSR = $false
    }
    
    IF (Test-Path $SignedByMSCADir){
        Remove-Item $SignedByMSCADir -Recurse -Force
    }
	New-Item -Force -ItemType directory -Path $SignedByMSCADir

    $CERTDIR = $SignedByMSCADir
	
    # check all parameter are defined, if not used auto-detect
    if ([string]::IsNullOrEmpty($config)) {
        $global:caConfig = get-ca-config
    }
	else {
		$global:caConfig = $config
	}
	
    if ([string]::IsNullOrEmpty($attrib)) {
        $val = get-ca-template
        $global:caAttrib = "CertificateTemplate:$val" 
    } else {
		$global:caAttrib = $attrib
	}
    if ([string]::IsNullOrEmpty($username)) {
        $global:caUserName = "Rainpole\Administrator"
    }else {
		$global:caUserName = $username
	}
	
    if ([string]::IsNullOrEmpty($password)) {
        $global:caPassword = "VMware1!"
    }else {
		$global:caPassword = $password
	}
                    
	# get MS Certificate Root CA from server
	
	get_Certificate_Root_CA
	
	# generate Config file, CSR, and signed with Certificate CA using certreq.exe
	GetPassword
	create_all_VVD_CRT("ConfigFiles")

	list-certs-generated
	
}

IF($CSR -or $all) {
    # generate all three, OpenSSL, CA and CSR certificates.
    if ($all) {
        $OpenSSLCASigned = $false
        $MSCASigned = $false
        $CSR = $true
    }
    
    IF (Test-Path $CSRDir){
        Remove-Item $CSRDir -Recurse -Force
    }
	New-Item -Force -ItemType directory -Path $CSRDir
    #md $CSRDir

    $CERTDIR = $CSRDir
	
	# generate Config file, CSR, and signed with Certificate CA using web enrollment
	create_all_VVD_CRT("ConfigFiles")
	
	list-certs-generated
	
	Write-Host
	Write-Host "**********************************************************************************"
	Write-Host "Copy the contents of each Certificate Request, $CSRDir\..\*.csr, file, 
and use it to request a signed certificate from your 3rd party CA. 

NOTE: The certificate must be Base64 encoded, and contain only the certificate, 
not the full certificate chain. If you are requesting this from another party, 
please also request the CA Root Certificate in Base 64 format as it is also required 
in later steps.

1. Store CA Root Certificate in $CSRDir\RootCA as Root64.cer
2. Store <NAME>.cer file in its corresponding <NAME>.csr directory
3. Execute  script with '-csr -extra' to generate different CERT format"
	Write-Host "**********************************************************************************"
	
}

# remove values stored in Powershell cache
Remove-Variable * -ErrorAction SilentlyContinue
Remove-item -Path "variable:p12Password" -ErrorAction SilentlyContinue
Remove-item -Path "variable:caConfig" -ErrorAction SilentlyContinue
Remove-item -Path "variable:caAttrib" -ErrorAction SilentlyContinue
Remove-item -Path "variable:caUserName" -ErrorAction SilentlyContinue
Remove-item -Path "variable:caPassword" -ErrorAction SilentlyContinue
$error.Clear()
exit

