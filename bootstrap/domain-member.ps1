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


Write-Host "Bootstrap script started..."


# turn off gcloud version checks
gcloud config set component_manager/disable_update_check true


$PreJoinScriptUrl = Get-GoogleMetadata "instance/attributes/pre-join-script-url"
If ($PreJoinScriptUrl) {
	Write-Host "Running pre-join script..."

        $TempFile = New-TemporaryFile
        $TempFile.MoveTo($TempFile.fullName + ".ps1")
        if ($PreJoinScriptUrl.StartsWith("gs://")) {
                gsutil -q cp $PreJoinScriptUrl $TempFile.FullName
        }
        else {
                (New-Object System.Net.WebClient).DownloadFile($PreJoinScriptUrl, $TempFile.FullName)          
        }
        Invoke-Expression $TempFile.FullName
        Remove-Item $TempFile.FullName -Force
}


Write-Host "Adding AD powershell tools..."
Add-WindowsFeature RSAT-AD-PowerShell


$Waiter = Get-GoogleMetadata "instance/attributes/wait-on"
If ($Waiter) {
	Write-Host "Waiting for $Waiter..."
	$RuntimeConfig = Get-GoogleMetadata "instance/attributes/runtime-config"
	Wait-RuntimeConfigWaiter -ConfigPath $RuntimeConfig -Waiter $Waiter
}


While (-Not $Joined) {

  # superstition
  Write-Host "Flushing DNS..."
  ipconfig /flushdns

  Write-Host "Configuring local admin..."
  # startup script runs as local system which cannot join domain
  # so do the join as local administrator using random password
  $LocalAdminPassword = New-RandomPassword
  Set-LocalUser Administrator -Password $LocalAdminPassword
  Enable-LocalUser Administrator
  $LocalAdminCredentials = New-Object `
        -TypeName System.Management.Automation.PSCredential `
        -ArgumentList "\Administrator",$LocalAdminPassword
  $Results = Invoke-Command -Credential $LocalAdminCredentials -ComputerName . -ScriptBlock {

    $Results = @{Joined=$False}

    Write-Host "Getting job metadata..."
    $Domain = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/attributes/domain-name
    $NetBiosName = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/attributes/netbios-name
    $GcsPrefix = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/attributes/gcs-prefix

    Write-Host "Fetching admin credentials..."
    # fetch domain admin credentials
    If ($GcsPrefix.EndsWith("/")) {
      $GcsPrefix = $GcsPrefix -Replace ".$"
    }
    $DomainAdminPassword = $(gsutil -q cat $GcsPrefix/output/domain-admin-password | ConvertTo-SecureString -AsPlainText -Force)
    $DomainAdminCredentials = New-Object `
        -TypeName System.Management.Automation.PSCredential `
        -ArgumentList "$NetBiosName\Administrator",$DomainAdminPassword

    Write-Host "Joining domain..."
    $CompChange = Add-Computer -DomainName $Domain -Credential $DomainAdminCredentials -PassThru -Verbose
    $Results.Joined = $CompChange.HasSucceeded
    If (-Not $Results.Joined) {
      Write-Host "Failed to join domain. Waiting to retry..."
      Start-Sleep 10
    }

    New-Object -TypeName PSObject -Property $Results

  }

  $Joined = $Results.Joined

}


$PostJoinScriptUrl = Get-GoogleMetadata "instance/attributes/post-join-script-url"
If ($PostJoinScriptUrl) {

	Write-Host "Configuring startup metadata for post-join script..."
	# set post join url as startup script then restart
	$name = Get-GoogleMetadata "instance/name"
	$zone = Get-GoogleMetadata "instance/zone"
	gcloud compute instances add-metadata "$name" --zone $zone --metadata "windows-startup-script-url=$PostJoinScriptUrl"

	Write-Host "Restarting..."
	Restart-Computer

}
Else {

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

}

