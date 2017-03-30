#!/usr/bin/env bash
../ldap-adapter -v -t -l :10389 -r localhost:3389 -baseDN "o=testers,c=test" -bindPWDFile pwd.txt&
../ldap-adapter -v -t -s -cert ./tests/cert_DONOTUSE.pem -key ./tests/key_DONOTUSE.pem -l :14389 -r localhost:3389 -baseDN "o=testers,c=test" &
go test -v
kill %1 %2
