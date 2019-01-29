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

Write-Host "Bootstrap script started..."


# get settings
$CtxClientId = Get-Setting "citrix/client-id"
$CtxClientSecretSS = Get-Setting "citrix/client-secret" -Secure $True
$CtxCustomerId = Get-Setting "citrix/customer-id"
$Prefix = Get-Setting "prefix"
$Suffix = Get-Setting "suffix"

# get metadata
$Domain = Get-GoogleMetadata "instance/attributes/domain-name"
$CtxMachineCatalog = Get-GoogleMetadata "instance/attributes/ctx-machine-catalog"
$CtxDeliveryGroup = Get-GoogleMetadata "instance/attributes/ctx-delivery-group"
$CtxHypervisorConnection = Get-GoogleMetadata "instance/attributes/ctx-hypervisor-connection"
$CtxCloudConnectors = Get-GoogleMetadata "instance/attributes/ctx-cloud-connectors"
$VdaDownloadUrl = Get-GoogleMetadata "instance/attributes/vda-download-url"


Write-Host "Downloading Citrix PoSH installer..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$TempFile = New-TemporaryFile
$TempFile.MoveTo($TempFile.FullName + ".exe")
$url = "http://download.apps.cloud.com/CitrixPoshSdk.exe"
(New-Object System.Net.WebClient).DownloadFile($url, $TempFile.FullName)

Write-Host "Running installer..."
Start-Process $TempFile.FullName "/q" -Wait


Write-Host "Cleaning up..."
Remove-Item $TempFile.FullName


Write-Host "Initializing Citrix PoSH SDK..."
Add-PSSnapin Citrix*
Set-XDCredentials -CustomerId $CtxCustomerId -ProfileType CloudAPI -APIKey $CtxClientId -SecretKey (Unwrap-SecureString $CtxClientSecretSS)


# download & install vda
Write-Host "Downloading VDA installer..."
$TempFile = New-TemporaryFile
$TempFile.MoveTo($TempFile.FullName + ".exe")
(New-Object System.Net.WebClient).DownloadFile($VdaDownloadUrl, $TempFile.FullName)


Write-Host "Waiting on Citrix setup from mgmt instance..."
$RuntimeConfig = Get-GoogleMetadata "instance/attributes/runtime-config"
Wait-RuntimeConfigWaiter -ConfigPath $RuntimeConfig -Waiter "waiter-ctx-mgmt-$Suffix"


Write-Host "Running installer..."
$Arguments = @(
	"/components"
	"vda,plugins"
	"/enable_hdx_ports"
	"/optimize"
	"/masterimage"
	"/enable_remote_assistance"
	"/controllers"
	"$CtxCloudConnectors"
	"/quiet"
	"/noreboot"
)
Start-Process $TempFile.FullName -ArgumentList $Arguments -Wait -NoNewWindow 


Write-Host "Cleaning up..."
Remove-Item $TempFile.FullName


Write-Host "Adding machine to catalog and delivery group..."
If ($CtxHypervisorConnection) {

Write-Host "Getting machine catalog..."
$BrokerCatalog = Get-BrokerCatalog $CtxMachineCatalog

$HypervisorConnection = Get-BrokerHypervisorConnection $CtxHypervisorConnection

$project = Get-GoogleMetadata "project/project-id"
$region = (Get-GoogleMetadata "instance/zone").Split("/")[-1] -Replace "-[^-]+$","" 
$name = Get-GoogleMetadata "instance/name"

$BrokerMachine = New-BrokerMachine -CatalogUid $BrokerCatalog.Uid -MachineName (Get-ADComputer "$Env:COMPUTERNAME").SID.Value -HostedMachineId "$project`:$region`:$name" -HypervisorConnectionUid $HypervisorConnection.Uid

}
Else {

  Do {
    Try {
#      $BrokerMachine = New-BrokerMachine -CatalogUid $BrokerCatalog.Uid -MachineName "$Domain\$Env:ComputerName"

      Write-Host "Getting machine catalog..."
      $BrokerCatalog = Get-BrokerCatalog $CtxMachineCatalog
      $BrokerMachine = New-BrokerMachine -CatalogUid $BrokerCatalog.Uid -MachineName (Get-ADComputer "$Env:COMPUTERNAME").SID.Value
      Break

    }
    Catch {
      Write-Host $_.ToString() + $_.InvocationInfo.PositionMessage
      Write-Host "Waiting to try again..."
      Sleep 15
    }
  } While ($True)

}
Add-BrokerMachine -DesktopGroup $CtxDeliveryGroup -InputObject @($BrokerMachine)


Write-Host "Configuring startup metadata..."
# remove startup script from metadata to prevent rerun on reboot
$name = Get-GoogleMetadata "instance/name"
$zone = Get-GoogleMetadata "instance/zone"
gcloud compute instances remove-metadata "$name" --zone $zone --keys windows-startup-script-url

Write-Host "Signaling completion..."
# flag completion of bootstrap requires beta gcloud component
$name = Get-GoogleMetadata "instance/name"
$RuntimeConfig = Get-GoogleMetadata "instance/attributes/runtime-config"
Set-RuntimeConfigVariable -ConfigPath $RuntimeConfig -Variable bootstrap/$name/success/time -Text (Get-Date -Format g)

