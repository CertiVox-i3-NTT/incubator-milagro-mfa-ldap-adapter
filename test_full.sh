#!/usr/bin/env bash
set -e
CURRENT=`pwd`

cd vendor/github.com/CertiVox-i3-NTT/asn1-ber
go test -v
cd $CURRENT

go build -o ldap-adapter
cd test
/bin/bash test.sh
