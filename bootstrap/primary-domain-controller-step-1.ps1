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


Write-Host "Persisting metadata..."
Set-Setting "prefix" (Get-GoogleMetadata "instance/attributes/prefix")
Set-Setting "suffix" (Get-GoogleMetadata "instance/attributes/suffix")


#Write-Host "Installing AD features in background..."
#Start-Job -ScriptBlock { Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools }
Write-Host "Installing AD features..."
Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools


Write-Host "Fetching metadata parameters..."
$Domain = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/attributes/domain-name
$NetBiosName = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/attributes/netbios-name
$KmsKey = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/attributes/kms-key
$GcsPrefix = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/attributes/gcs-prefix
#$RuntimeConfig = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/attributes/runtime-config


Write-Host "Configuring admin credentials..."
$SafeModeAdminPassword = New-RandomPassword
$LocalAdminPassword = New-RandomPassword

Set-LocalUser Administrator -Password $LocalAdminPassword
Enable-LocalUser Administrator

Write-Host "Saving encrypted credentials in GCS..."
If ($GcsPrefix.EndsWith("/")) {
  $GcsPrefix = $GcsPrefix -Replace ".$"
}
$TempFile = New-TemporaryFile

Unwrap-SecureString $LocalAdminPassword | gcloud kms encrypt --key $KmsKey --plaintext-file - --ciphertext-file $TempFile.FullName
gsutil cp $TempFile.FullName "$GcsPrefix/output/domain-admin-password.bin"

Unwrap-SecureString $SafeModeAdminPassword | gcloud kms encrypt --key $KmsKey --plaintext-file - --ciphertext-file $TempFile.FullName
gsutil cp $TempFile.FullName "$GcsPrefix/output/dsrm-admin-password.bin"

Remove-Item $TempFile.FullName -Force


Write-Host "Waiting for background jobs..."
Get-Job | Wait-Job


Write-Host "Creating AD forest..."
#Install-ADDSForest -NoRebootOnCompletion -DomainName $Domain -DomainNetbiosName $NetBiosName -InstallDNS -SafeModeAdministratorPassword $SafeModeAdminPassword -Force
$Params = @{
DomainName = $Domain
DomainNetbiosName = $NetBiosName
InstallDNS = $True
NoRebootOnCompletion = $True
SafeModeAdministratorPassword = $SafeModeAdminPassword
Force = $True
}
Install-ADDSForest @Params
#While ("Error" -eq (Install-ADDSForest @Params).Status) {
#        Write-Host "Install-ADDSForest failed.  Waiting to try again..."
#        Sleep 30
#}


Write-Host "Configuring startup metadata..."
$name = Get-GoogleMetadata "instance/name"
$zone = Get-GoogleMetadata "instance/zone"
$BootstrapFrom = Get-GoogleMetadata "instance/attributes/bootstrap-from"
gcloud compute instances add-metadata "$name" --zone $zone --metadata windows-startup-script-url=$BootstrapFrom/primary-domain-controller-step-2.ps1


Write-Host "Restarting computer..."
Restart-Computer

