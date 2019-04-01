#!/usr/bin/env bash

SUFFIX=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 6 | head -n 1)
TMP=$(mktemp)
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

cat <<EOF >$TMP
imports:
- path: $DIR/templates/citrix-on-gcp.jinja
resources:
- name: citrix-on-gcp-$SUFFIX
  type: $DIR/templates/citrix-on-gcp.jinja
  properties:
    admin: user:jeffallen@google.com 
    suffix: $SUFFIX
    bootstrap-from: gs://jeffallen-ext-citrix-3/bootstrap-v1
EOF

gcloud deployment-manager deployments create citrix-on-gcp-$SUFFIX --config=$TMP
rm $TMP

