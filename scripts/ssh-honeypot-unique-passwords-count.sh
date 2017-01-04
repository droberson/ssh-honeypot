#!/bin/bash

# ssh-honeypot-unique-passwords-count.sh -- by Daniel Roberson
# -- Prints a list of all passwords found in the logs with counts.
#
# -- usage: ssh-honeypot-unique-passwords-count.sh <logfile>

if [ ! $1 ]; then
  echo "FATAL: no input file!"
  echo "usage: $0 ssh-honeypot.log"
  exit 1
fi

grep "] ssh-honeypot " $1 >/dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "FATAL: $1 doesn't appear to be a ssh-honeypot log file"
  exit 1
fi

grep -v -e " Error exchanging keys: " -e "] ssh-honeypot " $1 |awk {'print $8'} |sort |uniq -c |sort -rn
