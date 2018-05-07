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

Param(
	[Parameter()][String][ValidateNotNullOrEmpty()]
	$Prefix = "citrix-on-gcp",
	[Parameter()][String]
	$Project,
	[Parameter()][String]
	$Suffix
)

# check gcloud is installed
Try {
	gcloud --version 1>$Null 2>&1
}
Catch {
	Write-Error "Please make sure gcloud is installed.  See https://cloud.google.com/sdk/downloads"
	Exit 1
}

# make sure we are authenticated in gcloud
$User = $(gcloud config get-value account 2>$Null)
if (-not $User) {
  Write-Error "User not authenticated.  Try 'gcloud auth login'."
  Exit 1
}
Write-Host "User: [$User]"

If (-not $Project) {
	$Project = $(gcloud config get-value core/project 2>$Null)
}
If (-not $Project) {
	Write-Error "Please specify a project or configure a default in gcloud"
	Exit 1
}
Write-Host "Project: [$Project]"

$ProjectNumber = $(gcloud projects describe "$Project" --format "value(projectNumber)")
Write-Host "Project Number: [$ProjectNumber]"

# see if user specified suffix, if not prompt for choice
If (-not $Suffix) {
	$Options = @(gcloud deployment-manager deployments list --format "value(name)" --project $Project | ? { $_ -match "^$Prefix-" })
	If ($Options.Length -eq 0) {
		Write-Error "Please specify a suffix and try again."
		Exit
	} Else {
		$Choice = $Null
		While (-not $Choice -or -not $Choice -match "\d+" -or $Choice -lt 1 -or $Choice -gt $Options.Length) {
			$Options | % { $i = 1 } { Write-Host "$i) $_"; $i++ }
			$Choice = Read-Host -Prompt "Please choose a deployment by number"
		}
		$Suffix = $Options[$Choice - 1] | Select-String -Pattern "[^-]+$" | % { $_.Matches } | % { $_.Value }
	}
}
Write-Host "Suffix: [$Suffix]"

Write-Host "Getting domain users for: $Prefix-$Suffix"
$Temp = New-TemporaryFile
gsutil cp "gs://$Prefix-$ProjectNumber-$Suffix/output/domain-users.bin" $Temp.FullName
gcloud kms decrypt --key "projects/$Project/locations/global/keyRings/$Prefix/cryptoKeys/domain-secrets-$Suffix" --ciphertext-file $Temp.FullName --plaintext-file -
Remove-Item $Temp.FullName

