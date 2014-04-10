#!/bin/sh
EMAIL=login-limit-$(date +%s)@restmail.net
declare -i PRELIMIT
DELAYLIMIT=20
PRELIMIT=$1-$DELAYLIMIT
export COMMAND="./ve/bin/fxa-client --email $EMAIL"
$COMMAND create --password 12345678
sleep 3
$COMMAND verify --password 12345678
sleep 3
$COMMAND login --password 87654321
$COMMAND login --password 87654321
$COMMAND login --password 87654321
$COMMAND login --password 87654321
$COMMAND login --password 87654321
$COMMAND login --password 87654321
$COMMAND login --password 87654321
$COMMAND login --password 87654321
$COMMAND login --password 87654321
$COMMAND login --password 87654321
$COMMAND login --password 87654321
echo '>>>>>>>>Expect Fail'
$COMMAND login --password 12345678
echo '>>>>>>>>sleep '$PRELIMIT' seconds'
sleep $PRELIMIT
echo '>>>>>>>>Expect Fail'
$COMMAND login --password 12345678
echo '>>>>>>>>sleep '$DELAYLIMIT' seconds'
sleep $DELAYLIMIT
echo '>>>>>>>>Expect Fail'
$COMMAND login --password 87654321
echo '>>>>>>>>Expect Success'
$COMMAND login --password 12345678
$COMMAND destroy --password 12345678
