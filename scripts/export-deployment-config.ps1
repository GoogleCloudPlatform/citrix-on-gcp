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

$deployment = $(gcloud deployment-manager deployments list --filter name:qldm --format "value(name)")

$manifest = $(gcloud deployment-manager deployments describe $deployment --format "value(deployment.manifest.basename())")

gcloud deployment-manager manifests describe $manifest --deployment $deployment --format "value(config.content)"

