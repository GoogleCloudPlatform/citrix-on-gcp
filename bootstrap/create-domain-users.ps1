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

$KmsKey = Get-GoogleMetadata "instance/attributes/kms-key"
$GcsPrefix = Get-GoogleMetadata "instance/attributes/gcs-prefix"

# create group for citrix users and add admins to the group
New-ADGroup -Name "Citrix Users" -GroupCategory Security -GroupScope Global -Description "Domain users with access to Citrix resources"
Add-ADGroupMember -Identity "Citrix Users" -Members "Domain Admins" # add domain admins to citrix users group

$DomainUsers = "domain-users:`n"

$Domain = Get-GoogleMetadata "instance/attributes/domain-name"
$Netbios = Get-GoogleMetadata "instance/attributes/netbios-name"
Set-Setting "domain" $Domain
Set-Setting "domains/$Domain/netbios-name" $Netbios

1..10 | % {
	$UserName = "user_$_"
	$Password = New-RandomPassword
	New-ADUser $UserName -AccountPassword $Password
	Enable-ADAccount $UserName
	Add-ADGroupMember -Identity "Citrix Users" -Members $UserName
	$DomainUsers += "- username: $UserName`n  password: $(Unwrap-SecureString $Password)`n"
	Set-Setting "domains/$Domain/users/$UserName/password" $(Unwrap-SecureString $Password) -Secure $True
}

If ($GcsPrefix.EndsWith("/")) {
  $GcsPrefix = $GcsPrefix -Replace ".$"
}
$TempFile = New-TemporaryFile

$DomainUsers | gcloud kms encrypt --key $KmsKey --plaintext-file - --ciphertext-file $TempFile.FullName
gsutil cp $TempFile.FullName "$GcsPrefix/output/domain-users.bin"

Remove-Item $TempFile.FullName -Force

