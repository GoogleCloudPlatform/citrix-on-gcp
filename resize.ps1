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
	$Suffix,
	[Parameter()][Int32]
	$Workers = 1
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


if (Get-Module -ListAvailable -Name Powershell-Yaml) {
} else {
    Write-Host "Installing Powershell-Yaml module..."
    Install-Module Powershell-Yaml -Force
}
Import-Module Powershell-Yaml

$deployment = "$Prefix-$Suffix"
$manifest = $(gcloud deployment-manager deployments describe $deployment --format 'value(deployment.manifest)' --project $Project).split('/')[-1]

Write-Host "Deployment: [$deployment]"
Write-Host "Manifest: [$manifest]"
Write-Host "Workers: [$workers]"

$yaml = (gcloud deployment-manager manifests describe $manifest --deployment $deployment --format 'yaml(config.content)' --project $Project) -Join "`n"
$obj = ConvertFrom-Yaml $yaml

$configPath = Join-Path "$PSScriptRoot" "resize-$Suffix.yml"
$templatePath = "templates/citrix-on-gcp.jinja"

$config = ConvertFrom-Yaml ($obj['config']['content'] -Replace "\0$", "")
$config['imports'][0]['path'] = $templatePath
$config['resources'][0]['properties']['workers'] = $workers
$config['resources'][0]['type'] = $templatePath
[System.IO.File]::WriteAllText($configPath, $(ConvertTo-Yaml $config), [System.Text.Encoding]::ASCII)

Write-Host "Previewing DM update..."
$instances = (gcloud deployment-manager deployments update $deployment --config "$configPath" --preview --flatten='resources[]' --project $Project --format='value(resources.name,resources.type,resources.update.state)') | Select-String -Pattern "`tcompute.v1.instance`tIN_PREVIEW$" | % { "$_".Split("`t")[0] }


Write-Host "Applying DM update..."
gcloud deployment-manager deployments update $deployment --project $Project


# gcloud may have timed out after 1200s waiting for deployment
# continue waiting until done
While ( $(gcloud deployment-manager operations list --project $Project --filter "TARGET:$Prefix-$Suffix AND TYPE:update" --format 'value(STATUS)') -ne 'DONE' ) {
        gcloud deployment-manager operations wait `
                $( gcloud deployment-manager operations list `
		--project $Project `
                --filter "TARGET:$Prefix-$Suffix AND TYPE:insert" `
                --format 'value(NAME)' ) `
		--project $Project

}


# set scopes on instances back to default to remove elevated bootstrap permissions
Write-Host "stopping/starting instances to reset service accounts and scopes to defaults..."
$Jobs = $instances | % {
	# work in parallel, grouping output
	Start-Job -ArgumentList $Project, $_, $Prefix, $Suffix -ScriptBlock {
		$Project = $args[0]
		$Instance = $args[1]
		$Prefix = $args[2]
		$Suffix = $args[3]
		$Deployment = "$Prefix-$Suffix"
		Write-Host "Setting default service account and scopes on $Instance..."
		$Url = $(gcloud deployment-manager resources describe $Instance --deployment $Deployment --project $Project --format "value(url)")
		gcloud compute instances stop $Url
		gcloud compute instances set-service-account $Url --no-service-account --no-scopes
		gcloud compute instances remove-tags $Url --tags=internet-nat
		gcloud compute instances start $Url
	}
}
$Jobs | % { Receive-Job -Job $_ -Wait }

