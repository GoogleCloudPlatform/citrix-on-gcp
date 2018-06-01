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



# Install Libre Office
Write-Host "installing libre office..."
$url = "https://downloadarchive.documentfoundation.org/libreoffice/old/6.0.4.2/win/x86_64/LibreOffice_6.0.4.2_Win_x64.msi"
$filetype = "msi"
$TempFile = New-TemporaryFile
$TempFile.MoveTo($TempFile.FullName + "." + $filetype)
(New-Object System.Net.WebClient).DownloadFile($url, $TempFile.FullName)

$MSIArguments = @(
    "/qb"
    "/i"
    $TempFile.FullName
    "/l*"
    "LibreOffice_install_log.txt"
)
Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow 

Remove-Item $TempFile.FullName -Force


# Install Gimp
Write-Host "installing gimp..."
$url = "https://download.gimp.org/pub/gimp/v2.10/windows/gimp-2.10.0-x64-setup.exe"
$filetype = "exe"
$TempFile = New-TemporaryFile
$TempFile.MoveTo($TempFile.FullName + "." + $filetype)
(New-Object System.Net.WebClient).DownloadFile($url, $TempFile.FullName)

$Arguments = @(
    "/SILENT"
    "/NORESTART"
)
Start-Process $TempFile.FullName -ArgumentList $Arguments -Wait -NoNewWindow 

Remove-Item $TempFile.FullName -Force


# Install 7-Zip to unpack Slicer
Write-Host "installing 7-zip..."
$url = "https://www.7-zip.org/a/7z1805-x64.msi"
$filetype = "msi"
$TempFile = New-TemporaryFile
$TempFile.MoveTo($TempFile.FullName + "." + $filetype)
(New-Object System.Net.WebClient).DownloadFile($url, $TempFile.FullName)

$MSIArguments = @(
    "/q"
    "/i"
    $TempFile.FullName
    'INSTALLDIR="C:\Program Files\7-Zip"'
)
Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow 

Remove-Item $TempFile.FullName -Force


# Install Slicer
Write-Host "installing slicer..."
$url = "http://slicer.kitware.com/midas3/download?bitstream=738956"
$filetype = "exe"
$TempFile = New-TemporaryFile
$TempFile.MoveTo($TempFile.FullName + "." + $filetype)
(New-Object System.Net.WebClient).DownloadFile($url, $TempFile.FullName)

$Arguments = @(
    "x"
    $TempFile.FullName
    "-oC:\Progra~1\Slicer"
)
Start-Process C:\Progra~1\7-Zip\7z.exe -ArgumentList $Arguments -Wait -NoNewWindow 

Remove-Item $TempFile.FullName -Force



Write-Host "Configuring startup metadata for post-join script..."
# set post join url as startup script then restart
$name = Get-GoogleMetadata "instance/name"
$zone = Get-GoogleMetadata "instance/zone"
$GcsPrefix = Get-GoogleMetadata "instance/attributes/gcs-prefix"
gcloud compute instances add-metadata "$name" --zone $zone --metadata "windows-startup-script-url=$GcsPrefix/bootstrap/domain-member.ps1"

Write-Host "Restarting..."
Restart-Computer


