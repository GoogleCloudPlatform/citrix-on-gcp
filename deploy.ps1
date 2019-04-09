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
	$CitrixCredsUrl = $(Read-Host "Citrix Creds URL"),
	[Parameter()][String][ValidateNotNullOrEmpty()]
	$VdaDownloadUrl = "https://storage.googleapis.com/citrix-on-gcp-demo/vda/VDAServerSetup_7.17.exe",
	[Parameter()][Boolean]
	$PowerManaged = $True,
	[Parameter()][Boolean]
	$UseMinimalResources = $False,   # designed for free tier
	[Parameter()][Boolean]
	$UseSSD = ! $UseMinimalResources # default free tier ssd quota isn't sufficient
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

# calulate relative path to repository root
$Root = $PSScriptRoot
Write-Host "Root: [$Root]"

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
    citrix-creds: $CitrixCredsUrl
    admin: user:$User

"@
If ($PowerManaged) {
  $ConfigYaml = $ConfigYaml + @"
    power-managed: $PowerManaged
"@
}
[System.IO.File]::WriteAllText($Temp.FullName, $ConfigYaml, [System.Text.Encoding]::ASCII)

# deploy template to prepare demo environment
Write-Host "Config: [$Temp]"
Write-Host "Deployment: [$Prefix-$Suffix]"

gcloud deployment-manager deployments create "$Prefix-$Suffix" `
--project $Project `
--config $Temp.FullName `
--async

