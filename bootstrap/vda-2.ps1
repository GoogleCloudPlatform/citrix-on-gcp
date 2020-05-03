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
        $Path   
        )       
        
        $GcsPrefix = Get-GoogleMetadata -Path "instance/attributes/gcs-prefix"
        If ($GcsPrefix.EndsWith("/")) { 
                $GcsPrefix = $GcsPrefix -Replace ".$"
        }
        $Value = gsutil -q cat "$GcsPrefix/settings/$Path"
        Return $Value

}


Function Set-Setting {
	Param (
	[Parameter(Mandatory=$True)][String][ValidateNotNullOrEmpty()]
	$Path,
	[Parameter(Mandatory=$True)][String][ValidateNotNullOrEmpty()]
	$Value
	)

	$GcsPrefix = Get-GoogleMetadata -Path "instance/attributes/gcs-prefix"
	If ($GcsPrefix.EndsWith("/")) {
		$GcsPrefix = $GcsPrefix -Replace ".$"
	}

	$TempFile = New-TemporaryFile
	$Value | Out-File -NoNewLine $TempFile.FullName
	gsutil -q cp $TempFile.FullName "$GcsPrefix/settings/$Path"
	Remove-Item $TempFile.FullName

}

Write-Host "Bootstrap script started..."



Write-Host "Getting Citrix Creds..."
$CitrixCredsUrl = Get-GoogleMetadata "instance/attributes/citrix-creds"
$CitrixCreds = gsutil -q cat $CitrixCredsUrl | ConvertFrom-Json
Write-Host "Using client [$($CitrixCreds.SecureClientId)]..."
$CtxClientId = $CitrixCreds.SecureClientId
$CtxClientSecret = $CitrixCreds.SecureClientSecret
$CtxCustomerId = $CitrixCreds.CustomerId

# get metadata
$Domain = Get-GoogleMetadata "instance/attributes/domain-name"
$CtxMachineCatalog = Get-GoogleMetadata "instance/attributes/machine-catalog"
$CtxDeliveryGroup = Get-GoogleMetadata "instance/attributes/delivery-group"
$CtxHypervisorConnection = Get-GoogleMetadata "instance/attributes/hypervisor-connection"
$CtxCloudConnectors = Get-GoogleMetadata "instance/attributes/cloud-connectors"
$VdaDownloadUrl = Get-GoogleMetadata "instance/attributes/vda-download-url"



Write-Host "Initializing Citrix PoSH SDK..."
Add-PSSnapin Citrix*
Set-XDCredentials -CustomerId $CtxCustomerId -ProfileType CloudAPI -APIKey $CtxClientId -SecretKey $CtxClientSecret



Write-Host "Waiting on Citrix setup from mgmt instance..."
$RuntimeConfig = Get-GoogleMetadata "instance/attributes/runtime-config"
$MgmtWaiter = Get-GoogleMetadata "instance/attributes/mgmt-waiter"
If ($RuntimeConfig -And $MgmtWaiter) { 
  Wait-RuntimeConfigWaiter -ConfigPath $RuntimeConfig -Waiter $MgmtWaiter
}

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


## vda install requires restart
#Restart-Computer

