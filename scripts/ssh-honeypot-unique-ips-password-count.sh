#!/bin/bash

# ssh-honeypot-unique-ips-password-count.sh -- by Daniel Roberson
# -- prints a list of unique IP addresses which have tried to authenticate
# -- to ssh-honeypot with a password with number of times they have tried.
#
# -- usage: ssh-honeypot-unique-ips-password-count.sh <logfile>

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

grep -v -e "Error exchanging keys" $1 -e "] FATAL" -e "] ssh-honeypot " | awk {'print $6'} |sort |uniq -c |sort -rn
