/* ssh-honeypot -- by Daniel Roberson (daniel(a)planethacker.net) 2016
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <libssh/libssh.h>
#include <libssh/server.h>

#include "config.h"


char *logfile = LOGFILE;
char *banner = BANNER;
char *rsakey = RSAKEY;
char *bindaddr = BINDADDR;
int console_output = 0;


/* usage() -- prints out usage instructions and exits the program
 */
void usage (const char *progname) {
  fprintf (stderr, "ssh-honeypot %s by %s\n\n", VERSION, AUTHOR);
  fprintf (stderr, "usage: %s [-?h -p <port> -l <file> -b <address> -r <file> -f <file>]\n", progname);
  fprintf (stderr, "\t-?/-h\t\t-- this help menu\n");
  fprintf (stderr, "\t-l <file>\t-- log file\n");
  fprintf (stderr, "\t-b <address>\t-- IP address to bind to\n");
  fprintf (stderr, "\t-r <file>\t-- specify RSA key to use\n");
  fprintf (stderr, "\t-f <file>\t-- specify location to PID file\n");
  fprintf (stderr, "\t-s\t\t-- print output to stdout\n");

  exit (EXIT_FAILURE);
}


/* log_entry() -- adds timestamped log entry
 *             -- displays output to stdout if console_output is true
 *             -- returns 0 on success, 1 on failure
 */
int log_entry (const char *fmt, ...) {
  FILE *fp;
  time_t t;
  va_list va;
  char *timestr;
  char buf[1024];


  time (&t);
  timestr = strtok (ctime (&t), "\n"); // banish newline character to the land
                                       // of wind and ghosts
  if ((fp = fopen (logfile, "a+")) == NULL) {
    fprintf (stderr, "Unable to open logfile %s: %s\n",
	     logfile,
	     strerror (errno));
    return 1;
  }

  va_start (va, fmt);
  vsprintf (buf, fmt, va);
  va_end (va);


  fprintf (fp, "[%s] %s\n", timestr, buf);

  if (console_output)
    printf ("[%s] %s\n", timestr, buf);
  
  fclose (fp);
  return 0;
}


/* log_ssh_attempt() -- logs ip, user, and pass to logfile
 */
int log_ssh_attempt (ssh_message message, ssh_session session) {
  int n;
  char ip[INET6_ADDRSTRLEN];
  struct sockaddr_storage tmp;
  struct sockaddr_in *sock;
  socklen_t address_len = sizeof(tmp);


  getpeername (ssh_get_fd (session), (struct sockaddr *)&tmp, &address_len);
  sock = (struct sockaddr_in *)&tmp;
  inet_ntop (AF_INET, &sock->sin_addr, ip, sizeof(ip));
  
  n = log_entry ("%s %s %s",
		 ip,
		 ssh_message_auth_user (message),
		 ssh_message_auth_password (message));

  return n;
}


/* handle_ssh_auth() -- handles ssh authentication requests, logging
 *                   -- appropriately.
 */
int handle_ssh_auth (ssh_session session) {
  ssh_message message;

  
  if (ssh_handle_key_exchange (session)) {
    log_entry ("Error exchanging keys: %s", ssh_get_error (session));
    return -1;
  }

  for (;;) {
    if ((message = ssh_message_get (session)) == NULL)
      break;

    if (ssh_message_subtype (message) == SSH_AUTH_METHOD_PASSWORD)
      log_ssh_attempt (message, session);

    ssh_message_reply_default (message);
    ssh_message_free (message);
  }

  return 0;
}


/* main() -- main entry point of program
 */
int main (int argc, char *argv[]) {
  char opt;
  unsigned short port = PORT;
  ssh_session session;
  ssh_bind sshbind;

  
  while ((opt = getopt (argc, argv, "h?p:dl:b:r:f:s")) != -1) {
    switch (opt) {
    case '?': /* print usage */
    case 'h': 
      usage (argv[0]);
      break;

    case 'p': /* listen port */
      port = atoi(optarg);
      break;

    case 'd': /* daemonize */
      break;

    case 'l': /* log file path */
      logfile = optarg;
      break;

    case 'b': /* IP to bind to */
      bindaddr = optarg;
      break;

    case 'r': /* path to rsa key */
      rsakey = optarg;
      break;

    case 'f': /* pid file location */
      break;
      
    case 's': /* Output to stdout */
      console_output = 1;
      break;

    default:
      usage (argv[0]);
    }
  }

  session = ssh_new ();
  sshbind = ssh_bind_new ();

  ssh_bind_options_set (sshbind, SSH_BIND_OPTIONS_BINDADDR, bindaddr);
  ssh_bind_options_set (sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
  ssh_bind_options_set (sshbind, SSH_BIND_OPTIONS_BANNER, banner);
  ssh_bind_options_set (sshbind, SSH_BIND_OPTIONS_RSAKEY, rsakey);

  if (ssh_bind_listen (sshbind) < 0) {
    log_entry ("ssh_bind_listen(): %s", ssh_get_error (sshbind));
    return EXIT_FAILURE;
  }


  for (;;) {
    if (ssh_bind_accept (sshbind, session) == SSH_ERROR) {
      log_entry ("ssh_bind_accept(): %s", ssh_get_error (sshbind));
      return EXIT_FAILURE;
    }

    switch (fork()) {
    case -1:
      log_entry ("fork(): %s", strerror (errno));
      return EXIT_FAILURE;
    case 0:
      exit (handle_ssh_auth (session));
    default:
      break;
    }
  }
  
  return EXIT_SUCCESS;
}
