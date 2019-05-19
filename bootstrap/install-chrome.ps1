#
#  Copyright 2019 Google Inc.
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

# Install Chrome
Write-Host "downloading chrome..."
$url = "https://dl.google.com/tag/s/dl/chrome/install/googlechromestandaloneenterprise64.msi"
$filetype = "msi"
$TempFile = New-TemporaryFile
$TempFile.MoveTo($TempFile.FullName + "." + $filetype)
(New-Object System.Net.WebClient).DownloadFile($url, $TempFile.FullName)

Write-Host "installing chrome..."
$MSIArguments = @(
    "/q"
    "/i"
    $TempFile.FullName
)
Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow

Remove-Item $TempFile.FullName -Force

