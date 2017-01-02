#!/bin/bash

# ssh-honeypot-unique-ips-scanners.sh -- by Daniel Roberson
# -- prints a list of unique IP addresses which have connected to
# -- ssh-honeypot, but did not try a password. This typically indicates
# -- a scan of some kind.
#
# -- usage: ssh-honeypot-unique-ips-scanners.sh <logfile>

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

grep -v -e "] ssh-honeypot " -e "FATAL" -e "] Error " $1 |awk {'print $6'} |sort |uniq -c |sort -rn >~/.temp-ip-list

while read ip; do
  echo -n "$ip "
  echo $ip |awk {'print $2'} |xargs geoiplookup |sed 's/GeoIP\ Country\ Edition\:\ //g'
done < ~/.temp-ip-list

rm -f ~/.temp-ip-list
