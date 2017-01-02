#!/bin/sh

# ssh-honeypot-pid-check.sh -- by Daniel Roberson
# -- simple script to respawn ssh-honeypot if it dies.
# -- meant to be placed in your crontab!
# --
# -- * * * * * /path/to/ssh-honeypot-pid-check.sh

# Season to taste:
PIDFILE="/var/run/ssh-honeypot.pid"
LOGFILE="/var/log/ssh-honeypot.log"
RSAFILE="/root/ssh-honeypot/ssh-honeypot.rsa"
SSHHPPATH="/root/ssh-honeypot/bin/ssh-honeypot -d -f $PIDFILE -l $LOGFILE -r $RSAFILE"

if [ ! -f $PIDFILE ]; then
    # PIDFILE doesnt exist!
    echo "ssh-honeypot not running. Attempting to start"
    $SSHHPPATH
    exit
else
    # PID file exists. check if its running!
    kill -0 `cat $PIDFILE |head -n 1` 2>/dev/null
    if [ $? -eq 0 ]; then
        exit 0
    else
        echo "ssh-honeypot not running. Attempting to start"
        $SSHHPPATH
    fi
fi

