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

Write-Host "Bootstrap script started..."


Write-Host "Configuring NTP..."
# use google internal time server
w32tm /config /manualpeerlist:"metadata.google.internal" /syncfromflags:manual /reliable:yes /update


# poll domain controller until it appears ready
Do {
  Try {
    $test = Get-ADDomain
  }
  Catch {
      Write-Host "Waiting for DC to become available..."
      Sleep 15
  }
}
Until ($test)


Write-Host "Configuring startup metadata..."
# remove startup script from metadata to prevent rerun on reboot
$name = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/name
$zone = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/zone
gcloud compute instances remove-metadata "$name" --zone $zone --keys windows-startup-script-url


Write-Host "Signaling completion..."
# flag completion of bootstrap requires beta gcloud component
$name = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/name
$RuntimeConfig = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/attributes/runtime-config
Set-RuntimeConfigVariable -ConfigPath $RuntimeConfig -Variable bootstrap/$name/success/time -Text (Get-Date -Format g)


Write-Output "Fetching metadata..."
$DomainName = Get-GoogleMetadata "instance/attributes/domain-name"
$NetbiosName = Get-GoogleMetadata "instance/attributes/netbios-name"
$BootstrapFrom = Get-GoogleMetadata "instance/attributes/bootstrap-from"
$GcsPrefix = Get-GoogleMetadata "instance/attributes/gcs-prefix"
If ($GcsPrefix.EndsWith("/")) {
  $GcsPrefix = $GcsPrefix -Replace ".$"
}

Write-Output "Fetching admin credentials..."
$DomainAdminPassword = $(gsutil -q cat $GcsPrefix/output/domain-admin-password | ConvertTo-SecureString -AsPlainText -Force)
$DomainAdminCredentials = New-Object `
        -TypeName System.Management.Automation.PSCredential `
        -ArgumentList "$NetBiosName\Administrator",$DomainAdminPassword

While (-Not $Domain) {
  $Domain = Get-ADDomain -Identity $DomainName
  If (-Not $Domain) {
    Write-Host "Failed to get domain. Waiting to retry..."
    Sleep 10
  }
}

Write-Host "Running script on PDC to populate domain..."
# download and run (as domain admin) user creation script
Invoke-Command -Credential $DomainAdminCredentials -ArgumentList "$BootstrapFrom/create-domain-users.ps1" -ScriptBlock {
        Param (
                $ScriptUrl
        )
        # turn off gcloud version checks
        gcloud config set component_manager/disable_update_check true

        $TempFile = New-TemporaryFile
        $TempFile.MoveTo($TempFile.fullName + ".ps1")
        if ($ScriptUrl.StartsWith("gs://")) {
                gsutil -q cp $ScriptUrl $TempFile.FullName
        }
        else {
                (New-Object System.Net.WebClient).DownloadFile($ScriptUrl, $TempFile.FullName)
        }
        Invoke-Expression $TempFile.FullName
        Remove-Item $TempFile.FullName -Force
}



