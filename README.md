# SSH Honeypot

This program listens for incoming ssh connections and logs the ip
address, username, and password used. This was written to gather
rudimentary intelligence on brute force attacks.

## Quickstart

### Linux
Make sure libssh is installed

    $ apt install libssh-dev

### OSX
Make sure that xcode is up to date. Then,


Install libssh

    $ brew install libssh

Copy the osx makefile over Makefile

    $ mv MakefileOSX Makefile

## Build and Run

    $ make
    $ ssh-keygen -t rsa -f ./ssh-honeypot.rsa
    $ bin/ssh-honeypot -r ./ssh-honepot.rsa


## Usage

    $ bin/ssh-keygen -h

## Syslog facilities.

As of version 0.0.5, this supports logging to syslog. This feature
is toggled with the -s flag. It is up to you to configure your
syslog facilities appropriately. This logs to LOG_AUTHPRIV which is
typically /var/log/auth.log. You may want to modify this to use
one of the LOG_LOCAL facilities if you are worried about password
leakage.

This was implemented to aggregate the data from several hosts into
a centralized spot.

## Banners
List available banners

    $ bin/ssh-keygen -b

Set banner string

    $ bin/ssh-keygen -b "mybanner string"

Set banner by index

    $ bib/ssh-keygen -i <banner index>
