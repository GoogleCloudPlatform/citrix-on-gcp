#!/usr/bin/env bash

CREDS=$1
while [ -z "$CREDS" ]; do
  echo "Citrix Creds URL? "
  read CREDS
done

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
    citrix-creds: $CREDS
EOF

echo "config: $TMP"
echo "deployment: citrix-on-gcp-$SUFFIX"
gcloud deployment-manager deployments create citrix-on-gcp-$SUFFIX --config=$TMP --async

