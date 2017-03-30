#!/usr/bin/env bash
go build -o ldap-adapter
GOOS=linux GOARCH=amd64 go build -o ldap-adapter.linux
GOOS=windows GOARCH=amd64 go build -o ldap-adapter.win64.exe

