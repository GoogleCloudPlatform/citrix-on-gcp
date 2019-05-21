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

Function GetBearerToken {
  Param (
    [Parameter(Mandatory=$true)]
    [string] $clientId,
    [Parameter(Mandatory=$true)]
    [string] $clientSecret
  )

  $postHeaders = @{"Content-Type"="application/json"}
  $body = @{
    "ClientId"=$clientId;
    "ClientSecret"=$clientSecret
  }
  $trustUrl = "https://trust.citrixworkspacesapi.net/root/tokens/clients"

  $response = Invoke-RestMethod -Uri $trustUrl -Method POST -Body (ConvertTo-Json $body) -Headers $postHeaders
  $bearerToken = $response.token

  return $bearerToken;
}

Function Remove-ResourceLocation {
  Param (
    [Parameter(Mandatory=$true)]
    [string] $id,
    [Parameter(Mandatory=$true)]
    [string] $customerId,
    [Parameter(Mandatory=$true)]
    [string] $bearerToken
  )

  $requestUri = [string]::Format("https://registry.citrixworkspacesapi.net/{0}/resourcelocations/{1}", $customerId, $id)
  $headers = @{
    "Content-Type" = "application/json"
    "Authorization" = "CWSAuth bearer=$bearerToken"
  }

  $response = Invoke-RestMethod -Uri $requestUri -Method DELETE -Headers $headers

  return $response;
}

Function Remove-EdgeServer {
  Param (
    [Parameter(Mandatory=$true)]
    [string] $id,
    [Parameter(Mandatory=$true)]
    [string] $customerId,
    [Parameter(Mandatory=$true)]
    [string] $bearerToken
  )

  $requestUri = [string]::Format("https://agenthub.citrixworkspacesapi.net/{0}/EdgeServers/{1}", $customerId, $id)
  $headers = @{
    "Content-Type" = "application/json"
    "Authorization" = "CWSAuth bearer=$bearerToken"
  }

  $response = Invoke-RestMethod -Uri $requestUri -Method DELETE -Headers $headers

  return $response;
}

Function List-EdgeServers {
  Param (
    [Parameter(Mandatory=$true)]
    [string] $locationId,
    [Parameter(Mandatory=$true)]
    [string] $customerId,
    [Parameter(Mandatory=$true)]
    [string] $bearerToken
  )

  $requestUri = [string]::Format("https://agenthub.citrixworkspacesapi.net/{0}/EdgeServers?Location={1}", $customerId, $locationId)
  $headers = @{
    "Content-Type" = "application/json"
    "Authorization" = "CWSAuth bearer=$bearerToken"
  }

  $response = Invoke-RestMethod -Uri $requestUri -Method GET -Headers $headers

  return $response;
}

Function List-ResourceLocations {
  Param (
    [Parameter(Mandatory=$true)]
    [string] $customerId,
    [Parameter(Mandatory=$true)]
    [string] $bearerToken
  )

  $requestUri = [string]::Format("https://registry.citrixworkspacesapi.net/{0}/resourcelocations/", $customerId)
  $headers = @{
    "Content-Type" = "application/json"
    "Authorization" = "CWSAuth bearer=$bearerToken"
  }

  $response = Invoke-RestMethod -Uri $requestUri -Method GET -Headers $headers

  return $response;
}

Function Get-ResourceLocation {
  Param (
    [Parameter(Mandatory=$true)]
    [string] $id,
    [Parameter(Mandatory=$true)]
    [string] $customerId,
    [Parameter(Mandatory=$true)]
    [string] $bearerToken
  )

  $requestUri = [string]::Format("https://registry.citrixworkspacesapi.net/{0}/resourcelocations/{1}", $customerId, $id)
  $headers = @{
    "Content-Type" = "application/json"
    "Authorization" = "CWSAuth bearer=$bearerToken"
  }

  $response = Invoke-RestMethod -Uri $requestUri -Method GET -Headers $headers

  return $response;
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


Write-Host "Getting settings..."
$CtxClientId = Get-Setting "citrix/client-id"
$CtxClientSecretSS = Get-Setting "citrix/client-secret" -Secure $True
$CtxCustomerId = Get-Setting "citrix/customer-id"
$Prefix = Get-Setting "prefix"
$Suffix = Get-Setting "suffix"


Write-Host "Adding PS snapins..."
Add-PSSnapin Citrix*


Write-Host "Initializing SDK..."
Set-XDCredentials -CustomerId $CtxCustomerId -ProfileType CloudAPI -APIKey $CtxClientId -SecretKey (Unwrap-SecureString $CtxClientSecretSS)


Write-Host "Removing catalog, desktop group, etc..."

$users = "CTX\Citrix Users"
$TSVDACatalogName = "Catalog-$Suffix"
$TSVDADGName = "Group-$Suffix"

# delete policy rules
Remove-BrokerAccessPolicyRule "$TSVDADGName-AG"
Remove-BrokerAccessPolicyRule "$TSVDADGName-Direct"
Remove-BrokerAppEntitlementPolicyRule "$TSVDADGName"


@(
@{
name="Gimp" # GIMP 2
path="C:\Program Files\GIMP 2\bin\gimp-2.10.exe"
},
@{
name="Slicer" # 3D Slicer 4.8.1
path="C:\Program Files\Slicer\Slicer.exe"
},
@{
name="Writer" # LibreOffice Writer
path="C:\Program Files\LibreOffice\program\swriter.exe"
},
@{
name="Calc" # LibreOffice Calc
path="C:\Program Files\LibreOffice\program\scalc.exe"
},
@{
name="Draw" # LibreOffice Draw
path="C:\Program Files\LibreOffice\program\sdraw.exe"
},
@{
name="Chrome" # Google Chrome Browser
path="C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
}
) | %{

$path = $_['path']
$name = $_['name']

Write-Host "Removing app..."
Write-Host "App Name: [$name]"

$Params = @{
Name = "$name-$Suffix"
}
Remove-BrokerApplication @Params

}


# remove delivery group
$Params = @{
Name = $TSVDADGName
}
Remove-BrokerDesktopGroup @Params

# remove catalog
$Params = @{
Name = $TSVDACatalogName
}
Remove-BrokerCatalog @Params


Write-Host "Getting resource location id..."
# remove resource location by id
$Token = GetBearerToken $CtxClientId (Unwrap-SecureString $CtxClientSecretSS)
$id = Get-Setting "citrix/resource-locations/$Prefix-$Suffix/id"


Write-Host "Removing cloud connectors..."
List-EdgeServers $id $CtxCustomerId $Token | %{
	Remove-EdgeServer $_.id $CtxCustomerId $Token
}


Write-Host "Removing resource location..."
Remove-ResourceLocation $id $CtxCustomerId $Token


$HostingServiceAccount = Get-GoogleMetadata "instance/attributes/hosting-connection-service-account"
If ($HostingServiceAccount) {

	Write-Host "Removing hosting connection..."

	Remove-Item -Path @("XDHyp:\Connections\Google-Cloud-$Suffix")
	Remove-BrokerHypervisorConnection -Name "Google-Cloud-$Suffix"

}


Write-Host "Signaling completion..."
# flag completion of bootstrap requires beta gcloud component
$name = Get-GoogleMetadata "instance/name"
$RuntimeConfig = Get-GoogleMetadata "instance/attributes/runtime-config"
Set-RuntimeConfigVariable -ConfigPath $RuntimeConfig -Variable cleanup/$name -Text (Get-Date -Format g)

