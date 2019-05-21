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

Function Disable-InternetExplorerESC {
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0
    Stop-Process -Name Explorer -Force
}


Write-Host "Bootstrap script started..."


#Write-Host "Disabling IE enhanced security..."
#Disable-InternetExplorerESC


Write-Host "Getting settings..."
$CtxClientId = Get-Setting "citrix/client-id"
$CtxClientSecretSS = Get-Setting "citrix/client-secret" -Secure $True
$CtxCustomerId = Get-Setting "citrix/customer-id"
$Prefix = Get-Setting "prefix"
$Suffix = Get-Setting "suffix"

Write-Host "CtxClientId: [$CtxClientId]"
Write-Host "CtxCustomerId: [$CtxCustomerId]"
Write-Host "Prefix: [$Prefix]"
Write-Host "Suffix: [$Suffix]"


Write-Host "Downloading installer..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$TempFile = New-TemporaryFile
$TempFile.MoveTo($TempFile.FullName + ".exe")
$url = "https://downloads.cloud.com/$CtxCustomerId/connector/cwcconnector.exe"
(New-Object System.Net.WebClient).DownloadFile($url, $TempFile.FullName)


Write-Host "Waiting on Citrix Resource Location..."
$RuntimeConfig = Get-GoogleMetadata "instance/attributes/runtime-config"
Wait-RuntimeConfigWaiter -ConfigPath $RuntimeConfig -Waiter "waiter-ctx-resloc"
$CtxResourceLocationId = Get-Setting "citrix/resource-locations/$Prefix-$Suffix/id"


Write-Host "Running installer..."
$CmdArgs = "/q /CustomerName:$CtxCustomerId /ClientId:$CtxClientID /ClientSecret:$(Unwrap-SecureString $CtxClientSecretSS) /Location:$CtxResourceLocationId /AcceptTermsOfService:true"
Start-Process -FilePath $TempFile.FullName -ArgumentList $CmdArgs -Wait


Write-Host "Cleaning up..."
Remove-Item $TempFile.FullName


Write-Host "Signaling Citrix Connector setup..."
$name = Get-GoogleMetadata "instance/name"
$RuntimeConfig = Get-GoogleMetadata "instance/attributes/runtime-config"
Set-RuntimeConfigVariable -ConfigPath $RuntimeConfig -Variable "setup/citrix/connector/$name" -Text (Get-Date -Format g)


Write-Host "Configuring startup metadata..."
# remove startup script from metadata to prevent rerun on reboot
$name = Get-GoogleMetadata "instance/name"
$zone = Get-GoogleMetadata "instance/zone"
gcloud compute instances remove-metadata "$name" --zone $zone --keys windows-startup-script-url


Write-Host "Signaling completion..."
# flag completion of bootstrap requires beta gcloud component
$name = Get-GoogleMetadata "instance/name"
$RuntimeConfig = Get-GoogleMetadata "instance/attributes/runtime-config"
Set-RuntimeConfigVariable -ConfigPath $RuntimeConfig -Variable "bootstrap/$name/success/time" -Text (Get-Date -Format g)


