#!/bin/bash

PREV_LINE_STAT=/var/log/crowdstrike/falconhoseclient/prev_last_line.tmp
LOG=/var/log/crowdstrike/falconhoseclient/output
CURL_LOG=/var/log/crowdstrike/falconhoseclient/curl_output
LINE=$(cat $LOG | wc -l)

if [ -f $PREV_LINE_STAT ]
then
   PREV_LINE=$(cat $PREV_LINE_STAT)
else
   PREV_LINE=0
fi

declare -i LINE_RANGE
LINE_RANGE=$LINE-$PREV_LINE
if [ $LINE_RANGE -lt 0 ]
then
  LINE_RANGE=$LINE
fi

# ENGINE
tail -n $LINE_RANGE $LOG > $CURL_LOG
#curl file://localhost/$CURL_LOG

#echo "LINE = $LINE"
#echo "LINE_RANGE is $LINE_RANGE"

echo $LINE > $PREV_LINE_STAT