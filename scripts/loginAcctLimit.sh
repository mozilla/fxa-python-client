#!/bin/sh
export PUBLIC_URL="https://api-accounts.stage.mozaws.net/"
EMAIL=login-limit-$(date +%s)@restmail.net
declare -i PRELIMIT
DELAYLIMIT=20
PRELIMIT=$1-$DELAYLIMIT
export COMMAND="./ve/bin/fxa-client --email $EMAIL"
$COMMAND --password 12345678 create
sleep 3
$COMMAND --password 12345678 verify
sleep 3
$COMMAND --password 87654321 login
$COMMAND --password 87654321 login
$COMMAND --password 87654321 login
$COMMAND --password 87654321 login
$COMMAND --password 87654321 login
$COMMAND --password 87654321 login
$COMMAND --password 87654321 login
$COMMAND --password 87654321 login
$COMMAND --password 87654321 login
$COMMAND --password 87654321 login
$COMMAND --password 87654321 login
echo '>>>>>>>>Expect Fail'
$COMMAND --password 12345678 login
echo '>>>>>>>>sleep '$PRELIMIT' seconds'
sleep $PRELIMIT
echo '>>>>>>>>Expect Fail'
$COMMAND --password 12345678 login 
echo '>>>>>>>>sleep '$DELAYLIMIT' seconds'
sleep $DELAYLIMIT
echo '>>>>>>>>Expect Fail'
$COMMAND --password 87654321 login
echo '>>>>>>>>Expect Success'
$COMMAND --password 12345678 login
$COMMAND --password 12345678 destroy
