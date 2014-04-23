#!/bin/sh
export PUBLIC_URL="https://api-accounts.stage.mozaws.net/"
EMAIL=email-limit-$(date +%s)@restmail.net
declare -i PRELIMIT
DELAYLIMIT=10
PRELIMIT=$1-$DELAYLIMIT
export COMMAND="./ve/bin/fxa-client --password 12345678 --email $EMAIL"
$COMMAND create
sleep 3
$COMMAND create
sleep 3
$COMMAND create
sleep 3
$COMMAND create
curl -X DELETE http://restmail.net/mail/$EMAIL

echo '>>>>>>>sleep '$PRELIMIT' seconds:'
sleep $PRELIMIT
echo '>>>>>>>>Expect Fail'
$COMMAND create

echo '>>>>>>>sleep '$DELAYLIMIT' seconds:'
sleep $DELAYLIMIT
echo '>>>>>create'
echo '>>>>>>>>Expect Success'
$COMMAND create
sleep 3
echo '>>>>> curl restmail:'
curl http://restmail.net/mail/$EMAIL
echo '>>>>>verify'
$COMMAND verify
echo '>>>>>login'
echo '>>>>>>>>Expect Success'
$COMMAND login
echo '>>>>>destroy'
$COMMAND destroy
