# SSH Honeypot

This program listens for incoming ssh connections and logs the ip
address, username, and password used. This was written to gather
rudimentary intelligence on brute force attacks.


## Quickstart

### Linux

Make sure headers/development packages are installed for:

- libssh
- openssl
- libjson-c
- libpcap


  apt install libssh-dev libjson-c-dev libpcap-dev libssl-dev


Build and Run

    make
    ssh-keygen -t rsa -f ./ssh-honeypot.rsa
    bin/ssh-honeypot -r ./ssh-honeypot.rsa


### OSX (experimental/unsupported)

_NOTE: Haven't tested json logging on OSX. This is officially
unsupported as I do not own any Macs to test or develop with._

Make sure that xcode is up to date.

Install libssh and json-c

    brew install libssh json-c

Specify MakefileOSX with make:

    make -f MakefileOSX


### Docker (experimental)

Please take a look at our [Docker documentation](docker/README.md).


## HASSH

As of version 0.2.0, ssh-honeypot attempts to calculate the HASSH of
the client software initiating sessions with ssh-honeypot. In short,
you can tell if the client is using OpenSSH, PuTTY, SecureCRT, ...


## Syslog facilities

As of version 0.0.5, this supports logging to syslog. This feature is
toggled with the -s flag. It is up to you to configure your syslog
facilities appropriately. This logs to LOG_AUTHPRIV which is typically
/var/log/auth.log. You may want to modify this to use one of the
LOG_LOCAL facilities if you are worried about password leakage.

This was implemented to aggregate the data from several hosts into a
centralized spot.


## Dropping privileges

As of version 0.0.8, you can drop root privileges of this program
after binding to a privileged port. You can now run this as _nobody_
on port 22 for example instead of root, but have to initially start it
as root:

    sudo bin/ssh-honeypot -p 22 -u nobody

Beware that this chowns the logfile to the user specified as well.


## Changing the Banner

List available banners

    bin/ssh-honeypot -b

Set banner string

    bin/ssh-honeypot -b "my banner string"

Set banner by index

    bin/ssh-honeypot -i <banner index>


## Systemd integration

On Linux you can install ssh-honeypot as a Systemd service so that it
automatically runs at system startup:

    make install
    systemctl enable --now ssh-honeypot

Before installing, check `ssh-honeypot.service` and modify it to run
with the options you want.

