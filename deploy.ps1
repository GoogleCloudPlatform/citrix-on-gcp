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
	[Parameter()][String][ValidateNotNullOrEmpty()]
	$Suffix = $(-Join ((48..57) + (97..122) | Get-Random -Count 6 | % {[char]$_})),
	[Parameter()][String][ValidateNotNullOrEmpty()]
	$Domain = "ctx-" + $Suffix + ".gcp",
	[Parameter()][String][ValidateNotNullOrEmpty()]
	$NetbiosName = "CTX-" + $Suffix.ToUpper(),
	[Parameter()][String]
	$Project,
	[Parameter()][String]
	$Region,
	[Parameter()][String]
	$Zone,
	[Parameter()][Int32]
	$Workers = 1,
	[Parameter()][String][ValidateNotNullOrEmpty()]
	$CTXSecureClientID = $(Read-Host "CTXSecureClientID"),
	[Parameter()][Security.SecureString][ValidateNotNullOrEmpty()]
	$CTXSecureClientSecret = $(Read-Host "CTXSecureClientSecret" -AsSecureString),
	[Parameter()][String][ValidateNotNullOrEmpty()]
	$CTXCustomerID = $(Read-Host "CTXCustomerID"),
	[Parameter()][String][ValidateNotNullOrEmpty()]
	$VdaDownloadUrl = "https://storage.googleapis.com/citrix-on-gcp-demo/vda/VDAServerSetup_1906.exe",
	[Parameter()][Boolean]
	$PowerManaged = $True,
	[Parameter()][Boolean]
	$UseMinimalResources = $False,   # designed for free tier
	[Parameter()][Boolean]
	$UseSSD = ! $UseMinimalResources # default free tier ssd quota isn't sufficient
)

Function Unwrap-SecureString() {
        Param(
                [System.Security.SecureString] $SecureString
        )
        Return (New-Object -TypeName System.Net.NetworkCredential -ArgumentList '', $SecureString).Password
}

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

# enable required api's
$RequiredAPIs = "compute","cloudkms","deploymentmanager","runtimeconfig","cloudresourcemanager","iam"
$EnabledAPIs = @(gcloud services list --project $Project | Select-Object -Skip 1 | Select-String -Pattern "^[^.]+" | % { $_.Matches } | % { $_.Value })
$DisabledAPIs = @($RequiredAPIs | ?{$EnabledAPIs -notcontains $_} | Sort-Object)
If ($DisabledAPIs.Length -Gt 0) {
	"Enabling APIs: [$($DisabledAPIs -Join " ")]"
	$Jobs = $DisabledAPIs | ForEach-Object {
		Start-Job -ArgumentList $_, $Project -ScriptBlock {
			$API = $args[0]
			$Project = $args[1]
			$Success = $False
			While (-not $Success) {
				Write-Host "Enabling API $API..."
				gcloud services enable "$API.googleapis.com" --project $Project
				$Success = ($LastExitCode -eq 0)
				If (-not $Success) {
					Write-Host "Waiting to retry enabling API: $API..."
					Start-Sleep -s 5
				}
			}
		}
	}
	# wait on jobs in sequence to avoid comingling output
	$Jobs | ForEach-Object { Receive-Job -Job $_ -Wait }
}

If (-not $Region) {
	$Region = $(gcloud config get-value compute/region 2>$Null)
}
If (-not $Region) {
	Write-Error "Please specify a region or configure a default in gcloud"
	Exit 1
}
Write-Host "Region: [$Region]"

# get zones in region
$Zones = @(gcloud compute zones list --project $Project --filter "region: $Region" --format "value(name)")

# use parameter zone if specified and exists within region
If (-not $Zone -or ($Zones -notcontains $Zone)) {
	# get gcloud default if set
	$Zone = $(gcloud config get-value compute/zone 2>$Null)
	# choose random zone if default isn't valid
	If (-not $Zone -or ($Zones -notcontains $Zone)) {
		$Zone = $Zones | Get-Random
	}
}
Write-Host "Primary Zone: [$Zone]"

# choose a different secondary zone in region
$SecondaryZone = $Zones | Where-Object { $_ -ne $Zone } | Get-Random
Write-Host "Secondary Zone: [$SecondaryZone]"

# look up project number
$ProjectNumber = $(gcloud projects describe "$Project" --format "value(projectNumber)")
Write-Host "Project Number: [$ProjectNumber]"

# calulate relative path to repository root
$Root = $PSScriptRoot
Write-Host "Root: [$Root]"

## create random suffix for disambiguating resources
#$Suffix = -join ((48..57) + (97..122) | Get-Random -Count 6 | % {[char]$_})
#echo "Deployment Suffix: [$Suffix]"

# create bucket and copy up bootstrap artifacts
$BucketName = "$Prefix-$ProjectNumber-$Suffix"
Write-Host "Bucket: [$BucketName]"
gsutil mb -p $Project gs://$BucketName
gsutil -m cp -r $(Join-Path "$Root" "bootstrap") gs://$BucketName/

# configure service accounts
$DefaultServiceAccount = "$ProjectNumber-compute@developer.gserviceaccount.com"
$AdminServiceAccountName = "admin-$Suffix"
$AdminServiceAccount = "$AdminServiceAccountName@$Project.iam.gserviceaccount.com"
gcloud iam service-accounts create $AdminServiceAccountName --display-name "Admin service account for bootstrapping domain-joined servers with elevated permissions" --project $Project
gcloud iam service-accounts add-iam-policy-binding $AdminServiceAccount --member "user:$User" --role "roles/iam.serviceAccountUser" --project $Project
gcloud projects add-iam-policy-binding $Project --member "serviceAccount:$AdminServiceAccount" --role "roles/editor"
$ServiceAccount = $AdminServiceAccount

Write-Host "Service Account: [$ServiceAccount]"

$CloudbuildServiceAccount = "$ProjectNumber@cloudbuild.gserviceaccount.com"
gcloud projects add-iam-policy-binding $Project --member "serviceAccount:$CloudbuildServiceAccount" --role "roles/iam.serviceAccountUser"
gcloud projects add-iam-policy-binding $Project --member "serviceAccount:$CloudbuildServiceAccount" --role "roles/compute.instanceAdmin.v1"
gcloud projects add-iam-policy-binding $Project --member "serviceAccount:$CloudbuildServiceAccount" --role "roles/cloudbuild.builds.builder"

Write-Host "Update roles of Cloud Build service account: [$CloudbuildServiceAccount]"

If ($PowerManaged) {

$CitrixServiceAccountName = "citrix-$Suffix"
$CitrixServiceAccount = "$CitrixServiceAccountName@$Project.iam.gserviceaccount.com"
gcloud iam service-accounts create $CitrixServiceAccountName --display-name "Service account for Citrix machine catalog for GCP" --project $Project
gcloud iam service-accounts add-iam-policy-binding $CitrixServiceAccount --member "serviceAccount:$AdminServiceAccount" --role "roles/iam.serviceAccountKeyAdmin" --project $Project
#gcloud iam roles create citrix.hosting_connection_$Suffix --project $Project --stage GA --permissions compute.instances.get,compute.instances.list,compute.instances.reset,compute.instances.reset,compute.instances.start,compute.instances.stop
#gcloud projects add-iam-policy-binding $Project --member "serviceAccount:$CitrixServiceAccount" --role "projects/$Project/roles/citrix.hosting_connection_$Suffix"
gcloud projects add-iam-policy-binding $Project --member "serviceAccount:$CitrixServiceAccount" --role "roles/viewer"
gcloud projects add-iam-policy-binding $Project --member "serviceAccount:$CitrixServiceAccount" --role "roles/compute.admin"
gcloud projects add-iam-policy-binding $Project --member "serviceAccount:$CitrixServiceAccount" --role "roles/storage.admin"
gcloud projects add-iam-policy-binding $Project --member "serviceAccount:$CitrixServiceAccount" --role "roles/cloudbuild.builds.editor"
gcloud projects add-iam-policy-binding $Project --member "serviceAccount:$CitrixServiceAccount" --role "roles/datastore.user"
gcloud projects add-iam-policy-binding $Project --member "serviceAccount:$CitrixServiceAccount" --role "roles/iam.serviceAccountUser"


Write-Host "Citrix Service Account: [$CitrixServiceAccount]"
}

# create kms keyring and key
$KmsKeyring = $Prefix
$KmsKeyName = "domain-secrets-$Suffix"
Write-Host "Keyring: [$KmsKeyring]"
Write-Host "Key: [$KmsKeyName]"

# create keyring if it doesn't already exist
gcloud kms keyrings describe $KmsKeyring --project $Project --location global 1>$Null 2>&1
If ($LastExitCode -ne 0) {
	gcloud kms keyrings create $KmsKeyring --project $Project --location global
}
gcloud kms keys create $KmsKeyName --project $Project --purpose=encryption --keyring $KmsKeyring --location global
$KmsKey = $(gcloud kms keys describe $KmsKeyName --keyring $KmsKeyring --project $Project --location global --format 'value(name)')

# set permissions to only allow encrypt/decrypt by current user and service account
$Temp = New-TemporaryFile
@"
{
  "bindings": [{
    "role": "roles/cloudkms.cryptoKeyDecrypter",
    "members": ["serviceAccount:$ServiceAccount", "user:$User"]
  }, {
    "role": "roles/cloudkms.cryptoKeyEncrypter",
    "members": ["serviceAccount:$ServiceAccount", "user:$User"]
  }]
}
"@ | Out-File $Temp.FullName -Encoding ASCII
gcloud kms keys set-iam-policy $KmsKey $Temp --project $Project
Remove-Item $Temp.FullName


# store citrix parameters in gcs encrypting the secret
Write-Host "Saving Citrix parameters..."
$Temp = New-TemporaryFile

$Prefix | Out-File $Temp.FullName -NoNewLine -Encoding ASCII
gsutil cp $Temp.FullName "gs://$BucketName/settings/prefix"

$Suffix | Out-File $Temp.FullName -NoNewLine -Encoding ASCII
gsutil cp $Temp.FullName "gs://$BucketName/settings/suffix"

$CTXSecureClientID | Out-File $Temp.FullName -NoNewLine -Encoding ASCII
gsutil cp $Temp.FullName "gs://$BucketName/settings/citrix/client-id"

$CTXCustomerID | Out-File $Temp.FullName -NoNewLine -Encoding ASCII
gsutil cp $Temp.FullName "gs://$BucketName/settings/citrix/customer-id"

Unwrap-SecureString $CTXSecureClientSecret | gcloud kms encrypt --key $KmsKey --plaintext-file - --ciphertext-file $Temp.FullName
gsutil cp $Temp.FullName "gs://$BucketName/settings/citrix/client-secret.bin"

Remove-Item $Temp.FullName

# make temporary config file for deployment manager initialization properties
$Temp = New-TemporaryFile

$ConfigYaml = @"
imports:
- path: $Root/templates/$Prefix.jinja

resources:
- name: $Prefix-$Suffix
  type: $Root/templates/$Prefix.jinja
  properties:
    suffix: $Suffix
    region: $Region
    zone: $Zone
    secondary-zone: $SecondaryZone
    service-account: $ServiceAccount
    gcs-prefix: gs://$BucketName
    kms-key: $KmsKey
    domain-name: $Domain
    netbios-name: $NetbiosName
    subnets:
    - region: $Region
      cidr: 10.128.0.0/20
    vda-download-url: $VdaDownloadUrl
    workers: $Workers
    minimal: $UseMinimalResources
    ssd: $UseSSD

"@
If ($PowerManaged) {
  $ConfigYaml = $ConfigYaml + @"
    hosting-connection-service-account: $CitrixServiceAccount
"@
}
[System.IO.File]::WriteAllText($Temp.FullName, $ConfigYaml, [System.Text.Encoding]::ASCII)

# deploy template to prepare tutorial environment
gcloud deployment-manager deployments create "$Prefix-$Suffix" `
--project $Project `
--config $Temp.FullName `
--async

Remove-Item $Temp.FullName

# gcloud may have timed out after 1200s waiting for deployment
# continue waiting until done
While ( $(gcloud deployment-manager operations list --project $Project --filter "TARGET:$Prefix-$Suffix AND TYPE:insert" --format 'value(STATUS)') -ne 'DONE' ) {
        gcloud deployment-manager operations wait `
                $( gcloud deployment-manager operations list `
		--project $Project `
                --filter "TARGET:$Prefix-$Suffix AND TYPE:insert" `
                --format 'value(NAME)' ) `
		--project $Project

}


#Write-Host "*** DEBUG EXIT ***"
#Exit


# set scopes on instances back to default to remove elevated bootstrap permissions
Write-Host "stopping/starting instances to reset service accounts and scopes to defaults..."
$Jobs = gcloud compute instances list --project $Project --format "value(name)" | ? { $_ -match "^ctx-.+-$Suffix$" } | ForEach-Object {
	# work in parallel, grouping output
	Start-Job -ArgumentList $Project, $_, $DefaultServiceAccount, $Prefix, $Suffix -ScriptBlock {
		$Project = $args[0]
		$Instance = $args[1]
		$DefaultServiceAccount = $args[2]
		$Prefix = $args[3]
		$Suffix = $args[4]
		$Deployment = "$Prefix-$Suffix"
		Write-Host "Setting default service account and scopes on $Instance..."
		$Url = $(gcloud deployment-manager resources describe $Instance --deployment $Deployment --project $Project --format "value(url)")
		gcloud compute instances stop $Url
		If ($Instance -Match "^ctx-xa-.*-$Suffix$") {
			gcloud compute instances set-service-account $Url --no-service-account --no-scopes
		}
		Else {
			gcloud compute instances set-service-account $Url --service-account $DefaultServiceAccount --scopes default
		}
		If ($Instance -NotMatch "^ctx-mgmt-$Suffix$") {
			gcloud compute instances start $Url
		}
	}
}
$Jobs | ForEach-Object { Receive-Job -Job $_ -Wait }

