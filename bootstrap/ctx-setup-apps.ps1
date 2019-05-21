#
#  Copyright 2018 Google Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

Function Set-RuntimeConfigVariable {
        Param(
		[Parameter(Mandatory=$True)][String] $ConfigPath,
		[Parameter(Mandatory=$True)][String] $Variable,
		[Parameter(Mandatory=$True)][String] $Text
        )

	$Auth = $(gcloud auth print-access-token)

	$Path = "$ConfigPath/variables"
	$Url = "https://runtimeconfig.googleapis.com/v1beta1/$Path"

	$Json = (@{
	name = "$Path/$Variable"
	text = $Text
	} | ConvertTo-Json)

	$Headers = @{
	Authorization = "Bearer " + $Auth
	}

	$Params = @{
	Method = "POST"
	Headers = $Headers
	ContentType = "application/json"
	Uri = $Url
	Body = $Json
	}

	Try {
		Return Invoke-RestMethod @Params
	}
	Catch {
	        $Reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
        	$ErrResp = $Reader.ReadToEnd() | ConvertFrom-Json
        	$Reader.Close()
		Return $ErrResp
	}

}

Function Get-RuntimeConfigWaiter {
	Param(
		[Parameter(Mandatory=$True)][String] $ConfigPath,
		[Parameter(Mandatory=$True)][String] $Waiter
	)

	$Auth = $(gcloud auth print-access-token)

	$Url = "https://runtimeconfig.googleapis.com/v1beta1/$ConfigPath/waiters/$Waiter"
	$Headers = @{
	Authorization = "Bearer " + $Auth
	}
	$Params = @{
	Method = "GET"
	Headers = $Headers
	Uri = $Url
	}

	Return Invoke-RestMethod @Params
}

Function Wait-RuntimeConfigWaiter {
	Param(
		[Parameter(Mandatory=$True)][String] $ConfigPath,
		[Parameter(Mandatory=$True)][String] $Waiter,
		[int] $Sleep = 60
	)
	$RuntimeWaiter = $Null
	While (($RuntimeWaiter -eq $Null) -Or (-Not $RuntimeWaiter.done)) {
		$RuntimeWaiter = Get-RuntimeConfigWaiter -ConfigPath $ConfigPath -Waiter $Waiter
		If (-Not $RuntimeWaiter.done) {
			Write-Host "Waiting for [$ConfigPath/waiters/$Waiter]..."
			Sleep $Sleep
		}
	}
	Return $RuntimeWaiter
}

Function New-RandomString {
	Param(
		[int] $Length = 10,
		[char[]] $AllowedChars = $Null
	)
	If ($AllowedChars -eq $Null) {
		(,(33,126)) | % { For ($a=$_[0]; $a -le $_[1]; $a++) { $AllowedChars += ,[char][byte]$a } }
	}
	For ($i=1; $i -le $Length; $i++) {
		$Temp += ( $AllowedChars | Get-Random )
	}
	Return $Temp
}

Function New-RandomPassword() {
	Param(
		[int] $Length = 16,
		[char[]] $AllowedChars = $Null
	)
	Return New-RandomString -Length $Length -AllowedChars $AllowedChars | ConvertTo-SecureString -AsPlainText -Force
}

Function Unwrap-SecureString() {
	Param(
		[System.Security.SecureString] $SecureString
	)
	Return (New-Object -TypeName System.Net.NetworkCredential -ArgumentList '', $SecureString).Password
}

Function Get-GoogleMetadata() {
	Param (
	[Parameter(Mandatory=$True)][String] $Path
	)
	Try {
		Return Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/$Path
	}
	Catch {
		Return $Null
	}
}

Function GetBearerToken {
  Param (
    [Parameter(Mandatory=$true)]
    [string] $clientId,
    [Parameter(Mandatory=$true)]
    [string] $clientSecret
  )

  $postHeaders = @{"Content-Type"="application/json"}
  $body = @{
    "ClientId"=$clientId;
    "ClientSecret"=$clientSecret
  }
  $trustUrl = "https://trust.citrixworkspacesapi.net/root/tokens/clients"

  $response = Invoke-RestMethod -Uri $trustUrl -Method POST -Body (ConvertTo-Json $body) -Headers $postHeaders
  $bearerToken = $response.token

  return $bearerToken;
}

Function New-ResourceLocation {
  Param (
    [Parameter(Mandatory=$true)]
    [string] $name,
    [Parameter(Mandatory=$true)]
    [string] $customerId,
    [Parameter(Mandatory=$true)]
    [string] $bearerToken
  )

  $requestUri = [string]::Format("https://registry.citrixworkspacesapi.net/{0}/resourcelocations", $customerId)
  $headers = @{
    "Content-Type" = "application/json"
    "Accept" = "application/json"
    "Authorization" = "CWSAuth bearer=$bearerToken"
  }
  $body = @{
    "name" = $name
  }

  $response = Invoke-RestMethod -Uri $requestUri -Method POST -Body (ConvertTo-Json $body) -Headers $headers

  return $response;
}

Function Get-Setting {
	Param (
	[Parameter(Mandatory=$True)][String][ValidateNotNullOrEmpty()]
	$Path,
	[Parameter()][Boolean]
	$Secure = $False
	)

	$GcsPrefix = Get-GoogleMetadata -Path "instance/attributes/gcs-prefix"
	If ($GcsPrefix.EndsWith("/")) {
		$GcsPrefix = $GcsPrefix -Replace ".$"
	}

	If ($Secure) {
		$KmsKey = Get-GoogleMetadata -Path "instance/attributes/kms-key"
		$TempFile = New-TemporaryFile
		gsutil -q cp "$GcsPrefix/settings/$Path.bin" "$TempFile.FullName"
		$Value = gcloud kms decrypt --key "$KmsKey" --ciphertext-file "$TempFile.FullName" --plaintext-file - | ConvertTo-SecureString -AsPlainText -Force
		Remove-Item $TempFile.FullName
	}
	Else {
		$Value = gsutil -q cat "$GcsPrefix/settings/$Path"
	}

	Return $Value

}


Function Set-Setting {
	Param (
	[Parameter(Mandatory=$True)][String][ValidateNotNullOrEmpty()]
	$Path,
	[Parameter(Mandatory=$True)][String][ValidateNotNullOrEmpty()]
	$Value,
	[Parameter()][Boolean]
	$Secure = $False
	)

	$GcsPrefix = Get-GoogleMetadata -Path "instance/attributes/gcs-prefix"
	If ($GcsPrefix.EndsWith("/")) {
		$GcsPrefix = $GcsPrefix -Replace ".$"
	}

	If ($Secure) {
		$KmsKey = Get-GoogleMetadata -Path "instance/attributes/kms-key"
		$TempFile = New-TemporaryFile
		$TempFileEnc = New-TemporaryFile
		$Value | Out-File -NoNewLine $TempFile.FullName
		gcloud kms encrypt --key "$KmsKey" --ciphertext-file $TempFileEnc.FullName --plaintext-file $TempFile.FullName
		gsutil -q cp $TempFileEnc.FullName "$GcsPrefix/settings/$Path.bin"
		Remove-Item $TempFileEnc.FullName
		Remove-Item $TempFile.FullName
	}
	Else {
		$TempFile = New-TemporaryFile
		$Value | Out-File -NoNewLine $TempFile.FullName
		gsutil -q cp $TempFile.FullName "$GcsPrefix/settings/$Path"
		Remove-Item $TempFile.FullName
	}

}

Function Disable-InternetExplorerESC {
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
    Stop-Process -Name Explorer
}


Write-Host "Bootstrap script started..."


Write-Output "Getting metadata..."
$NetBiosName = Get-GoogleMetadata "instance/attributes/netbios-name"
$KmsKey = Get-GoogleMetadata "instance/attributes/kms-key"
$GcsPrefix = Get-GoogleMetadata "instance/attributes/gcs-prefix"
If ($GcsPrefix.EndsWith("/")) {
  $GcsPrefix = $GcsPrefix -Replace ".$"
}


Write-Output "Fetching admin credentials..."
# fetch and decrypt domain admin and dsrm passwords
$TempFile = New-TemporaryFile
gsutil cp $GcsPrefix/output/domain-admin-password.bin $TempFile.FullName
$DomainAdminPassword = $(gcloud kms decrypt --key $KmsKey --ciphertext-file $TempFile.FullName --plaintext-file - | ConvertTo-SecureString -AsPlainText -Force)
Remove-Item $TempFile.FullName
$DomainAdminCredentials = New-Object `
        -TypeName System.Management.Automation.PSCredential `
        -ArgumentList "$NetBiosName\Administrator",$DomainAdminPassword


Write-Host "Running script on PDC to populate domain..."
# download and run (as domain admin) user creation script
Invoke-Command -ComputerName  (Get-ADDomain).PDCEmulator -Credential $DomainAdminCredentials -ArgumentList "$GcsPrefix/bootstrap/create-domain-users.ps1" -ScriptBlock {
	Param (
		$ScriptUrlGcs
	)
	$TempFile = New-TemporaryFile
	$TempFile.MoveTo($TempFile.fullName + ".ps1")
	gsutil cp $ScriptUrlGcs $TempFile.FullName
	Invoke-Expression $TempFile.FullName
	Remove-Item $TempFile.FullName -Force
}


Write-Host "Getting settings..."
$CtxClientId = Get-Setting "citrix/client-id"
$CtxClientSecretSS = Get-Setting "citrix/client-secret" -Secure $True
$CtxCustomerId = Get-Setting "citrix/customer-id"
$Prefix = Get-Setting "prefix"
$Suffix = Get-Setting "suffix"


Write-Host "Getting API bearer token..."
$Token = GetBearerToken $CtxClientId (Unwrap-SecureString $CtxClientSecretSS)


Write-Host "Creating Resource Location..."
$ResLoc = New-ResourceLocation "$Prefix-$Suffix" $CtxCustomerId $Token
Set-Setting ("citrix/resource-locations/" + $ResLoc.name + "/id") $ResLoc.id


Write-Host "Signalling Citrix Resource Location setup..."
$name = Get-GoogleMetadata "instance/name"
$RuntimeConfig = Get-GoogleMetadata "instance/attributes/runtime-config"
Set-RuntimeConfigVariable -ConfigPath $RuntimeConfig -Variable "setup/citrix/resloc/$name" -Text (Get-Date -Format g)


Write-Host "Downloading installer..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$TempFile = New-TemporaryFile
$TempFile.MoveTo($TempFile.FullName + ".exe")
$url = "http://download.apps.cloud.com/CitrixPoshSdk.exe"
(New-Object System.Net.WebClient).DownloadFile($url, $TempFile.FullName)

Write-Host "Running installer..."
Start-Process $TempFile.FullName "/q" -Wait


Write-Host "Cleaning up..."
Remove-Item $TempFile.FullName


Write-Host "Adding PS snapins..."
Add-PSSnapin Citrix*


Write-Host "Initializing SDK..."
Set-XDCredentials -CustomerId $CtxCustomerId -ProfileType CloudAPI -APIKey $CtxClientId -SecretKey (Unwrap-SecureString $CtxClientSecretSS)


Write-Host "Waiting on Citrix Connector..."
$RuntimeConfig = Get-GoogleMetadata "instance/attributes/runtime-config"
Wait-RuntimeConfigWaiter -ConfigPath $RuntimeConfig -Waiter "waiter-ctx-connector"


Write-Host "Getting zone..."
While (-Not ($Zone = Get-ConfigZone -Name $Prefix-$Suffix)) {
  Write-host "Waiting for zone..."
  Sleep 5
}


Write-Host "Creating catalog, desktop group, etc..."
$NetbiosName = Get-GoogleMetadata "instance/attributes/netbios-name"
$users = "$NetbiosName\Citrix Users"
$MachineCatalogName = "Catalog-$Suffix"
$DeliveryGroupName = "Group-$Suffix"


$HostingServiceAccount = Get-GoogleMetadata "instance/attributes/hosting-connection-service-account"
If ($HostingServiceAccount) {

	New-BrokerCatalog  -AllocationType "Random" -Description "" -IsRemotePC $False -MachinesArePhysical $False -MinimumFunctionalLevel "L7_9" -Name $MachineCatalogName -PersistUserChanges "OnLocal" -ProvisioningType "Manual" -Scope @() -SessionSupport "MultiSession" -ZoneUid $Zone.Uid

} Else {

	New-BrokerCatalog  -AllocationType "Random" -Description "" -IsRemotePC $False -MachinesArePhysical $True -MinimumFunctionalLevel "L7_9" -Name $MachineCatalogName -PersistUserChanges "OnLocal" -ProvisioningType "Manual" -Scope @() -SessionSupport "MultiSession" -ZoneUid $Zone.Uid

}


$DG = New-BrokerDesktopGroup  -ColorDepth "TwentyFourBit" -DeliveryType "DesktopsAndApps" -DesktopKind "Shared" -InMaintenanceMode $False -IsRemotePC $False -MinimumFunctionalLevel "L7_9" -Name $DeliveryGroupName -OffPeakBufferSizePercent 10 -PeakBufferSizePercent 10 -PublishedName $DeliveryGroupName -Scope @() -SecureIcaRequired $False -SessionSupport "MultiSession" -ShutdownDesktopsAfterUse $False -TimeZone "UTC"

New-BrokerAppEntitlementPolicyRule -DesktopGroupUid $DG.Uid -Enabled $True -IncludedUserFilterEnabled $False -Name $DeliveryGroupName

$AdObj = New-Object System.Security.Principal.NTAccount($users)
$strSID = $AdObj.Translate([System.Security.Principal.SecurityIdentifier])

New-BrokerAccessPolicyRule -AllowedConnections "NotViaAG" -AllowedProtocols @("HDX","RDP") -AllowedUsers "Filtered" -AllowRestart $True -DesktopGroupUid $DG.Uid -Enabled $True -IncludedSmartAccessFilterEnabled $True -IncludedUserFilterEnabled $True -IncludedUsers @($strSID.Value) -Name "$DeliveryGroupName-Direct"

New-BrokerAccessPolicyRule -AllowedConnections "ViaAG" -AllowedProtocols @("HDX","RDP") -AllowedUsers "Filtered" -AllowRestart $True -DesktopGroupUid $DG.Uid -Enabled $True -IncludedSmartAccessFilterEnabled $True -IncludedSmartAccessTags @() -IncludedUserFilterEnabled $True -IncludedUsers @($strSID.Value) -Name "$DeliveryGroupName-AG"


@(
@{
name="Gimp" # GIMP 2
path="C:\Program Files\GIMP 2\bin\gimp-2.10.exe"
},
@{
name="Slicer" # 3D Slicer 4.8.1
path="C:\Program Files\Slicer\Slicer.exe"
},
@{
name="Writer" # LibreOffice Writer
path="C:\Program Files\LibreOffice\program\swriter.exe"
},
@{
name="Calc" # LibreOffice Calc
path="C:\Program Files\LibreOffice\program\scalc.exe"
},
@{
name="Draw" # LibreOffice Draw
path="C:\Program Files\LibreOffice\program\sdraw.exe"
},
@{
name="Chrome" # Google Chrome Browser
path="C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
}
) | %{

$path = $_['path']
$name = $_['name']

Write-Host "Registering app..."
Write-Host "App Name: [$name]"
Write-Host "App Path: [$path]"

$ctxIcon = Get-BrokerIcon -FileName "$path" -index 0
$brokerIcon = New-BrokerIcon -EncodedIconData $ctxIcon.EncodedIconData

New-BrokerApplication -ApplicationType "HostedOnDesktop" -CommandLineArguments "" -CommandLineExecutable "$path" -CpuPriorityLevel "Normal" -DesktopGroup $DG.Uid -Enabled $True -IgnoreUserHomeZone $False -MaxPerUserInstances 0 -MaxTotalInstances 0 -Name "$name-$Suffix" -Priority 0 -PublishedName "$name-$Suffix" -SecureCmdLineArgumentsEnabled $True -ShortcutAddedToDesktop $False -ShortcutAddedToStartMenu $False -UserFilterEnabled $False -Visible $True -WaitForPrinterCreation $False -IconUid $brokerIcon.Uid

}


$HostingServiceAccount = Get-GoogleMetadata "instance/attributes/hosting-connection-service-account"
If ($HostingServiceAccount) {

Write-Host "Creating hosting connection..."

$Project = Get-GoogleMetadata "project/project-id"

$TempFile = New-TemporaryFile
gcloud iam service-accounts keys create $TempFile.FullName --iam-account "$HostingServiceAccount"

$pk = (Get-Content -Path $TempFile.FullName | ConvertFrom-Json).private_key
$pw = $pk -Replace "\n",""

$HostingConnection = New-Item -ConnectionType "Custom" -CustomProperties "" -HypervisorAddress @("https://cloud.google.com/") -Path @("XDHyp:\Connections\Google-Cloud-$Suffix") -PluginId "GcpPluginFactory" -Scope @() -Password $pw -UserName $HostingServiceAccount -ZoneUid $Zone.Uid -Persist

New-BrokerHypervisorConnection -HypHypervisorConnectionUid $HostingConnection.HypervisorConnectionUid

Remove-Item $TempFile.FullName -Force

}


# remove startup script from metadata to prevent rerun on reboot
$name = Get-GoogleMetadata "instance/name"
$zone = Get-GoogleMetadata "instance/zone"
gcloud compute instances remove-metadata "$name" --zone $zone --keys windows-startup-script-url

Write-Host "Signaling completion..."
# flag completion of bootstrap requires beta gcloud component
$name = Get-GoogleMetadata "instance/name"
$RuntimeConfig = Get-GoogleMetadata "instance/attributes/runtime-config"
Set-RuntimeConfigVariable -ConfigPath $RuntimeConfig -Variable bootstrap/$name/success/time -Text (Get-Date -Format g)

