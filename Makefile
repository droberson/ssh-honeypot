CC=clang
CFLAGS=-Wall -static-libgcc
LIBS=-lssh -ljson-c

RSA=/etc/ssh-honeypot/ssh-honeypot.rsa

ssh-honeypot:
	$(CC) $(CFLAGS) -o bin/ssh-honeypot src/ssh-honeypot.c $(LIBS)

clean:
	rm -f *~ src/*~ bin/ssh-honeypot src/*.o

install: ssh-honeypot install-etc $(RSA)

install-etc:
	install -m 755 bin/ssh-honeypot /usr/local/bin/
	install -d /etc/ssh-honeypot
	install -m 644 ssh-honeypot.service /etc/ssh-honeypot/
	ln -sf /etc/ssh-honeypot/ssh-honeypot.service /etc/systemd/system/
	@echo
	@echo "You can enable ssh-honeypot at startup with: systemctl enable --now ssh-daemon"

$(RSA):
	ssh-keygen -t rsa -f $(RSA) -N ''

