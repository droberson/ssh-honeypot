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

