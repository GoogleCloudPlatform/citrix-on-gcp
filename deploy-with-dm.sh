#!/usr/bin/env bash

SUFFIX=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 6 | head -n 1)
TMP=$(mktemp)
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
USER="$(gcloud auth list --filter "ACTIVE:*" --format "value(ACCOUNT)")"

cat <<EOF >$TMP
imports:
- path: $DIR/templates/citrix-on-gcp.jinja
resources:
- name: citrix-on-gcp-$SUFFIX
  type: $DIR/templates/citrix-on-gcp.jinja
  properties:
    admin: user:$USER
    suffix: $SUFFIX
    bootstrap-from: gs://jeffallen-ext-citrix-4/bootstrap-v1
    citrix-creds: gs://jeffallen-ext-citrix-4/citrix-creds.json
    minimal: True
EOF

echo "config: $TMP"
echo "deployment: citrix-on-gcp-$SUFFIX"
gcloud deployment-manager deployments create citrix-on-gcp-$SUFFIX --config=$TMP --async
#rm $TMP

