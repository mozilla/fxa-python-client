#!/bin/sh
export PUBLIC_URL=https://api.accounts.firefox.com/
export COMMAND="./ve/bin/fxa-client --password 12345678"
$COMMAND --email user-monitor@restmail.net create
sleep 2
$COMMAND --email user-monitor@restmail.net verify
curl --silent  -X DELETE http://restmail.net/mail/user-monitor@restmail.net 
$COMMAND --email user-monitor@restmail.net login
$COMMAND --email user-monitor@restmail.net destroy


