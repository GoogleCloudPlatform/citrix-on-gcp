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


$ServiceAccountName = "admin-$Suffix"
$ServiceAccountEmail = "$ServiceAccountName@$Project.iam.gserviceaccount.com"
$GcsPrefix = "gs://$Prefix-$ProjectNumber-$Suffix"

Write-Host "Stop/start to elevate mgmt service account for cleanup..."
$Jobs = gcloud compute instances list --project $Project --format "value(name)" | ? { $_ -eq "ctx-mgmt-$Suffix" } | ForEach-Object {
        # work in parallel, grouping output
        Start-Job -ArgumentList $Project, $_, $ServiceAccountEmail, "$Prefix-$Suffix", "$GcsPrefix/bootstrap/ctx-cleanup-apps.ps1" -ScriptBlock {
                $Project = $args[0]
                $Instance = $args[1]
                $AdminServiceAccount = $args[2]
                $Deployment = $args[3]
                $ShutdownScriptUrl = $args[4]
                Write-Host "Configuring $Instance for cleanup..."
                $Url = $(gcloud deployment-manager resources describe $Instance --deployment $Deployment --project $Project --format "value(url)")
                gcloud compute instances stop $Url
                gcloud compute instances add-metadata $Url --metadata "windows-startup-script-url=$ShutdownScriptUrl"
		gcloud compute instances set-service-account $Url --service-account $AdminServiceAccount --scopes cloud-platform
                gcloud compute instances start $Url
        }
}
$Jobs | ForEach-Object { Receive-Job -Job $_ -Wait }


#Write-Host "*** DEBUG EXIT ***"
#Exit


# wait for cleanup script to complete
gcloud beta runtime-config configs waiters create waiter-cleanup-$Suffix --success-cardinality-path "cleanup" --config-name config-$Suffix --timeout 1200 --project $Project


Write-Host "Cleaning up deployment: $Prefix-$Suffix"

# cleanup deployment manager deployments
gcloud deployment-manager deployments delete "$Prefix-$Suffix" --project $Project --quiet

# destroy key versions
gcloud kms keys versions list --key "domain-secrets-$Suffix" --location global --keyring $Prefix --project $Project --format "value(NAME)" | % { gcloud kms keys versions destroy $_ --project $Project }


# remove permissions on key (key itself cannot be deleted)
$Temp = New-TemporaryFile
@"
bindings:
"@ | Out-File $Temp.FullName -Encoding ASCII
gcloud kms keys set-iam-policy "domain-secrets-$Suffix" $Temp.FullName --location global --keyring $Prefix --project $Project
Remove-Item $Temp.FullName

# remove service account
gcloud projects remove-iam-policy-binding $Project --member "serviceAccount:$ServiceAccountEmail" --role "roles/editor"
gcloud iam service-accounts delete $ServiceAccountEmail --project $Project --quiet

# remove bucket
gsutil -m rm -rf $GcsPrefix

