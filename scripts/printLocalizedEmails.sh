#!/bin/sh
epoch=$(date +%s)
# create &> /dev/null
export COMMAND="./ve/bin/fxa-client --password 12345678"
$COMMAND --email ca$epoch@restmail.net --lang ca create
$COMMAND --email cs$epoch@restmail.net --lang cs create &> /dev/null
$COMMAND --email cy$epoch@restmail.net --lang cy create &> /dev/null
$COMMAND --email de$epoch@restmail.net --lang de create &> /dev/null
$COMMAND --email es$epoch@restmail.net --lang es create &> /dev/null
$COMMAND --email fr$epoch@restmail.net --lang fr create &> /dev/null
$COMMAND --email fy$epoch@restmail.net --lang fy create &> /dev/null
$COMMAND --email he$epoch@restmail.net --lang he create &> /dev/null
$COMMAND --email hu$epoch@restmail.net --lang hu create &> /dev/null
$COMMAND --email id$epoch@restmail.net --lang id create &> /dev/null
$COMMAND --email it$epoch@restmail.net --lang it create &> /dev/null
$COMMAND --email ko$epoch@restmail.net --lang ko create &> /dev/null
$COMMAND --email lt$epoch@restmail.net --lang lt create &> /dev/null
$COMMAND --email nb-NO$epoch@restmail.net --lang nb-NO create &> /dev/null
$COMMAND --email nl$epoch@restmail.net --lang nl create &> /dev/null
$COMMAND --email pa$epoch@restmail.net --lang pa create &> /dev/null
$COMMAND --email pl$epoch@restmail.net --lang pl create &> /dev/null
$COMMAND --email pt-BR$epoch@restmail.net --lang pt-BR create &> /dev/null
$COMMAND --email rm$epoch@restmail.net --lang rm create &> /dev/null
$COMMAND --email ru$epoch@restmail.net --lang ru create &> /dev/null
$COMMAND --email sk$epoch@restmail.net --lang sk create &> /dev/null
$COMMAND --email sq$epoch@restmail.net --lang sq create &> /dev/null
$COMMAND --email sr$epoch@restmail.net --lang sr create &> /dev/null
$COMMAND --email sr-LATN$epoch@restmail.net --lang sr-LATN create &> /dev/null
$COMMAND --email sv$epoch@restmail.net --lang sv create &> /dev/null
$COMMAND --email tr$epoch@restmail.net --lang tr create &> /dev/null
$COMMAND --email zh-CN$epoch@restmail.net --lang zh-CN create &> /dev/null
$COMMAND --email zh-TW$epoch@restmail.net --lang zh-TW create &> /dev/null
sleep 5
# print emails
./scripts/getRestmailText cs$epoch@restmail.net
./scripts/getRestmailText cy$epoch@restmail.net
./scripts/getRestmailText de$epoch@restmail.net
./scripts/getRestmailText es$epoch@restmail.net
./scripts/getRestmailText fr$epoch@restmail.net
./scripts/getRestmailText fy$epoch@restmail.net
./scripts/getRestmailText hu$epoch@restmail.net
./scripts/getRestmailText it$epoch@restmail.net
./scripts/getRestmailText ko$epoch@restmail.net
./scripts/getRestmailText lt$epoch@restmail.net
./scripts/getRestmailText nb-NO$epoch@restmail.net
./scripts/getRestmailText nl$epoch@restmail.net
./scripts/getRestmailText pl$epoch@restmail.net
./scripts/getRestmailText pt-BR$epoch@restmail.net
./scripts/getRestmailText rm$epoch@restmail.net
./scripts/getRestmailText ru$epoch@restmail.net
./scripts/getRestmailText sk$epoch@restmail.net
./scripts/getRestmailText sq$epoch@restmail.net
./scripts/getRestmailText sr$epoch@restmail.net
./scripts/getRestmailText sr-LATN$epoch@restmail.net
./scripts/getRestmailText sv$epoch@restmail.net
./scripts/getRestmailText zh-CN$epoch@restmail.net
./scripts/getRestmailText zh-TW$epoch@restmail.net


# destroy &> /dev/null
$COMMAND --email ca$epoch@restmail.net --lang ca destroy
$COMMAND --email cs$epoch@restmail.net --lang cs destroy &> /dev/null
$COMMAND --email cy$epoch@restmail.net --lang cy destroy &> /dev/null
$COMMAND --email de$epoch@restmail.net --lang de destroy &> /dev/null
$COMMAND --email es$epoch@restmail.net --lang es destroy &> /dev/null
$COMMAND --email fr$epoch@restmail.net --lang fr destroy &> /dev/null
$COMMAND --email fy$epoch@restmail.net --lang fy destroy &> /dev/null
$COMMAND --email he$epoch@restmail.net --lang he destroy &> /dev/null
$COMMAND --email hu$epoch@restmail.net --lang hu destroy &> /dev/null
$COMMAND --email id$epoch@restmail.net --lang id destroy &> /dev/null
$COMMAND --email it$epoch@restmail.net --lang it destroy &> /dev/null
$COMMAND --email ko$epoch@restmail.net --lang ko destroy &> /dev/null
$COMMAND --email lt$epoch@restmail.net --lang lt destroy &> /dev/null
$COMMAND --email nb-NO$epoch@restmail.net --lang nb-NO destroy &> /dev/null
$COMMAND --email nl$epoch@restmail.net --lang nl destroy &> /dev/null
$COMMAND --email pa$epoch@restmail.net --lang pa destroy &> /dev/null
$COMMAND --email pl$epoch@restmail.net --lang pl destroy &> /dev/null
$COMMAND --email pt-BR$epoch@restmail.net --lang pt-BR destroy &> /dev/null
$COMMAND --email rm$epoch@restmail.net --lang rm destroy &> /dev/null
$COMMAND --email ru$epoch@restmail.net --lang ru destroy &> /dev/null
$COMMAND --email sk$epoch@restmail.net --lang sk destroy &> /dev/null
$COMMAND --email sq$epoch@restmail.net --lang sq destroy &> /dev/null
$COMMAND --email sr$epoch@restmail.net --lang sr destroy &> /dev/null
$COMMAND --email sr-LATN$epoch@restmail.net --lang sr-LATN destroy &> /dev/null
$COMMAND --email sv$epoch@restmail.net --lang sv destroy &> /dev/null
$COMMAND --email tr$epoch@restmail.net --lang tr destroy &> /dev/null
$COMMAND --email zh-CN$epoch@restmail.net --lang zh-CN destroy &> /dev/null
$COMMAND --email zh-TW$epoch@restmail.net --lang zh-TW destroy &> /dev/null
