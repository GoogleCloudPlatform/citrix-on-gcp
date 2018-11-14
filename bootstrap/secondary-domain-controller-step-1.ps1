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


Write-Output "Bootstrap script started..."


If ("true" -like (Get-GoogleMetadata "instance/attributes/remove-address")) {
        Write-Host "Removing external address..."
        $name = Get-GoogleMetadata "instance/name"
        $zone = Get-GoogleMetadata "instance/zone"
        gcloud compute instances delete-access-config $name --zone $zone
}


Write-Output "Fetching metadata parameters..."
$DomainControllerAddress = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/attributes/domain-controller-address
$Domain = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/attributes/domain-name
$NetBiosName = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/attributes/netbios-name
$KmsKey = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/attributes/kms-key
$GcsPrefix = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/attributes/gcs-prefix
$RuntimeConfig = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/attributes/runtime-config
$Waiter = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/attributes/wait-on


Write-Output "Installing AD features..."
Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools


## remaining script has external dependencies, so invoke waiter before continuing
Wait-RuntimeConfigWaiter -ConfigPath $RuntimeConfig -Waiter $Waiter


Write-Output "Fetching admin credentials..."
# fetch and decrypt domain admin and dsrm passwords
If ($GcsPrefix.EndsWith("/")) {
  $GcsPrefix = $GcsPrefix -Replace ".$"
}
$TempFile = New-TemporaryFile
gsutil cp $GcsPrefix/output/domain-admin-password.bin $TempFile.FullName
$DomainAdminPassword = $(gcloud kms decrypt --key $KmsKey --ciphertext-file $TempFile.FullName --plaintext-file - | ConvertTo-SecureString -AsPlainText -Force)
gsutil cp $GcsPrefix/output/dsrm-admin-password.bin $TempFile.FullName
$SafeModeAdminPassword = $(gcloud kms decrypt --key $KmsKey --ciphertext-file $TempFile.FullName --plaintext-file - | ConvertTo-SecureString -AsPlainText -Force)
Remove-Item $TempFile.FullName
$DomainAdminCredentials = New-Object `
        -TypeName System.Management.Automation.PSCredential `
        -ArgumentList "$NetBiosName\Administrator",$DomainAdminPassword


Write-Output "Configuring network..."
# reconfigure dhcp address as static to avoid warnings during dcpromo
$IpAddr = Get-NetIPAddress -InterfaceAlias Ethernet -AddressFamily IPv4
$IpConf = Get-NetIPConfiguration -InterfaceAlias Ethernet
Set-NetIPInterface `
	-InterfaceAlias Ethernet `
	-Dhcp Disabled
New-NetIPAddress `
	-InterfaceAlias Ethernet `
	-IPAddress $IpAddr.IPAddress `
	-AddressFamily IPv4 `
	-PrefixLength $IpAddr.PrefixLength `
	-DefaultGateway $IpConf.IPv4DefaultGateway.NextHop

# set dns to domain controller
Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses $DomainControllerAddress

# above can cause network blip, so wait until metadata server is responsive
$HaveMetadata = $False
While( ! $HaveMetadata ) { Try {
        Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/ 1>$Null 2>&1
        $HaveMetadata = $True
} Catch {
        Write-Output "Waiting on metadata..."
        Start-Sleep 5
} }
Write-Output "Contacted metadata server. Proceeding..."


Write-Output "Promoting to domain controller..."
$Params = @{
DomainName = $Domain
Credential = $DomainAdminCredentials
NoRebootOnCompletion = $True
SafeModeAdministratorPassword = $SafeModeAdminPassword
Force = $True
}
While ("Error" -eq (Install-ADDSDomainController @Params).Status) {
	Write-Host "Install-ADDSDomainController failed.  Waiting to try again..."
	Sleep 30
}


Write-Host "Configuring startup metadata..."
$name = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/name
$zone = Invoke-RestMethod -Headers @{"Metadata-Flavor" = "Google"} -Uri http://169.254.169.254/computeMetadata/v1/instance/zone
gcloud compute instances add-metadata "$name" --zone $zone --metadata windows-startup-script-url=$GcsPrefix/bootstrap/secondary-domain-controller-step-2.ps1


Write-Output "Restarting computer..."
Restart-Computer

