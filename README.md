# SSH Honeypot

This program listens for incoming ssh connections and logs the ip
address, username, and password used. This was written to gather
rudimentary intelligence on brute force attacks.

## Quick start
- ensure libssh is installed (apt install libssh-dev)
- edit src/config.h
- ssh-keygen -t rsa (save to non-default location!)
- make
- bin/ssh-honeypot -r ssh-honeypot.rsa

## Syslog facilities.

As of version 0.0.5, this supports logging to syslog. This feature
is toggled with the -s flag. It is up to you to configure your
syslog facilities appropriately. This logs to LOG_AUTHPRIV which is
typically /var/log/auth.log. You may want to modify this to use
one of the LOG_LOCAL facilities if you are worried about password
leakage.

This was implemented to aggregate the data from several hosts into
a centralized spot.
