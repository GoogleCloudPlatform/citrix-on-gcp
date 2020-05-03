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

Write-Output "Fetching metadata..."
$DomainName = Get-GoogleMetadata "instance/attributes/domain-name"
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

Write-Host "Running script on PDC to populate domain..."
# download and run (as domain admin) user creation script
Invoke-Command -ComputerName (Get-ADDomain -Identity $DomainName).PDCEmulator -Credential $DomainAdminCredentials -ArgumentList "$BootstrapFrom/create-domain-users.ps1" -ScriptBlock {
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


# delete instance
$name = Get-GoogleMetadata "instance/name"
$zone = Get-GoogleMetadata "instance/zone"
gcloud compute instances delete "$name" --zone "$zone"

