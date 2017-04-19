/* ssh-honeypot -- by Daniel Roberson (daniel(a)planethacker.net) 2016-2017
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <syslog.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <libssh/libssh.h>
#include <libssh/server.h>

#include "config.h"

static struct banner_info_s {
  const char *str, *info;
} banners[] = {
  {"",  "No banner"},
  {"OpenSSH_5.9p1 Debian-5ubuntu1.4", "Ubuntu 12.04"},
  {"OpenSSH_7.2p2 Ubuntu-4ubuntu2.1", "Ubuntu 16.04"},
  {"OpenSSH_6.6.1",                   "openSUSE 42.1"},
  {"OpenSSH_6.7p1 Debian-5+deb8u3",   "Debian 8.6"}
};

const size_t num_banners = sizeof banners / sizeof *banners;

char *logfile = LOGFILE;
char *pidfile = PIDFILE;
char *rsakey = RSAKEY;
char *bindaddr = BINDADDR;
int console_output = 1;
int daemonize = 0;
int use_syslog = 0;

/* usage() -- prints out usage instructions and exits the program
 */
static void usage (const char *progname) {
  fprintf (stderr, "ssh-honeypot %s by %s\n\n", VERSION, AUTHOR);

  fprintf (stderr, "usage: %s "
    "[-?h -p <port> -a <address> -b <index> -l <file> -r <file> -f <file>]\n",
    progname);
  fprintf (stderr, "\t-?/-h\t\t-- this help menu\n");
  fprintf (stderr, "\t-p <port>\t-- listen port\n");
  fprintf (stderr, "\t-a <address>\t-- IP address to bind to\n");
  fprintf (stderr, "\t-l <file>\t-- log file\n");
  fprintf (stderr, "\t-s\t\t-- toggle syslog usage. Default: %s\n",
	   use_syslog ? "on" : "off");
  fprintf (stderr, "\t-r <file>\t-- specify RSA key to use\n");
  fprintf (stderr, "\t-f <file>\t-- specify location to PID file\n");
  fprintf (stderr, "\t-b\t\t-- list available banners\n");
  fprintf (stderr, "\t-b <string> \t-- specify banner string (max 255 characters)\n");
  fprintf (stderr, "\t-i <index>\t-- specify banner index\n");

  exit (EXIT_FAILURE);
}

/* pr_banners() -- prints out a list of available banner options
 */
static void pr_banners () {
  size_t i;


  fprintf (stderr, "Available banners: [index] banner (description)\n");

  for (i = 0; i < num_banners; i++) {
    struct banner_info_s *banner = banners + i;
    fprintf (stderr, "[%zu] %s (%s)\n", i, banner->str, banner->info);
  }

  fprintf (stderr, "Total banners: %zu\n", num_banners);
}


/* log_entry() -- adds timestamped log entry
 *             -- displays output to stdout if console_output is true
 *             -- returns 0 on success, 1 on failure
 */
static int log_entry (const char *fmt, ...) {
  int n;
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

  if (use_syslog)
    syslog (LOG_INFO | LOG_AUTHPRIV, "[%s] %s", timestr, buf);

  n = fprintf (fp, "[%s] %s\n", timestr, buf);

  if (console_output)
    printf ("[%s] %s\n", timestr, buf);

  fclose (fp);
  return n;
}


/* get_ssh_ip() -- obtains IP address via ssh_session
 */
static char *get_ssh_ip (ssh_session session) {
  static char ip[INET6_ADDRSTRLEN];
  struct sockaddr_storage tmp;
  struct sockaddr_in *s;
  socklen_t address_len = sizeof(tmp);


  getpeername (ssh_get_fd (session), (struct sockaddr *)&tmp, &address_len);
  s = (struct sockaddr_in *)&tmp;
  inet_ntop (AF_INET, &s->sin_addr, ip, sizeof(ip));

  return ip;
}


/* handle_ssh_auth() -- handles ssh authentication requests, logging
 *                   -- appropriately.
 */
static int handle_ssh_auth (ssh_session session) {
  ssh_message message;
  char *ip;


  ip = get_ssh_ip (session);

  if (ssh_handle_key_exchange (session)) {
    log_entry ("%s Error exchanging keys: %s", ip, ssh_get_error (session));
    return -1;
  }

  for (;;) {
    if ((message = ssh_message_get (session)) == NULL)
      break;

    if (ssh_message_subtype (message) == SSH_AUTH_METHOD_PASSWORD) {
      log_entry ("%s %s %s",
		 ip,
		 ssh_message_auth_user (message),
		 ssh_message_auth_password (message));
    }

    ssh_message_reply_default (message);
    ssh_message_free (message);
  }

  return 0;
}


/* write_pid_file() -- writes PID to PIDFILE
 */
static void write_pid_file (char *path, pid_t pid) {
  FILE *fp;

  printf("path %s\n", path);
  fp = fopen (path, "w");

  if (fp == NULL) {
    log_entry ("FATAL: Unable to open PID file %s: %s\n",
	       path,
	       strerror (errno));

    exit (EXIT_FAILURE);
  }

  fprintf (fp, "%d", pid);
  fclose (fp);
}


/* main() -- main entry point of program
 */
int main (int argc, char *argv[]) {
  pid_t pid, child;
  int opt;
  unsigned short port = PORT, banner_index = 1;
  const char *banner = banners[1].str;
  ssh_session session;
  ssh_bind sshbind;


  while ((opt = getopt (argc, argv, "h?p:dl:b:i:r:f:s")) != -1) {
    switch (opt) {
    case 'p': /* listen port */
      port = atoi(optarg);
      break;

    case 'd': /* daemonize */
      daemonize = 1;
      console_output = 0;
      break;

    case 'l': /* log file path */
      logfile = optarg;
      break;

    case 'a': /* IP to bind to */
      bindaddr = optarg;
      break;

    case 'r': /* path to rsa key */
      rsakey = optarg;
      break;

    case 'f': /* pid file location */
      pidfile = optarg;
      break;

    case 's': /* toggle syslog */
      use_syslog = !use_syslog ? 1 : 0;
      break;

    case 'i':
      banner_index = atoi(optarg);

      if (banner_index >= num_banners) {
          fprintf (stderr, "FATAL: Invalid banner index\n");
          exit (EXIT_FAILURE);
      }

      banner = banners[banner_index].str;
      break;

    case 'b':
      banner = optarg;
      break;

    case '?': /* print usage */
    case 'h':
      if (optopt == 'i' || optopt == 'b') {
        pr_banners();
        return EXIT_FAILURE;
      }

    default:
      usage (argv[0]);
    }
  }

  signal (SIGCHLD, SIG_IGN);

  if (daemonize == 1) {
    pid = fork();

    if (pid < 0) {
      log_entry ("FATAL: fork(): %s\n", strerror (errno));
      exit (EXIT_FAILURE);
    }

    else if (pid > 0) {
      write_pid_file (pidfile, pid);
      exit (EXIT_SUCCESS);
    }

    printf ("ssh-honeypot %s by %s started on port %d. PID %d\n",
	    VERSION,
	    AUTHOR,
	    port,
	    getpid());
  }

  log_entry ("ssh-honeypot %s by %s started on port %d. PID %d",
	     VERSION,
	     AUTHOR,
	     port,
	     getpid());

  session = ssh_new ();
  sshbind = ssh_bind_new ();

  ssh_bind_options_set (sshbind, SSH_BIND_OPTIONS_BINDADDR, bindaddr);
  ssh_bind_options_set (sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
  ssh_bind_options_set (sshbind, SSH_BIND_OPTIONS_BANNER, banner);
  ssh_bind_options_set (sshbind, SSH_BIND_OPTIONS_RSAKEY, rsakey);

  if (ssh_bind_listen (sshbind) < 0) {
    log_entry ("FATAL: ssh_bind_listen(): %s", ssh_get_error (sshbind));

    if (daemonize == 1)
      printf ("FATAL: ssh_bind_listen(): %s\n", ssh_get_error (sshbind));

    exit (EXIT_FAILURE);
  }

  for (;;) {
    if (ssh_bind_accept (sshbind, session) == SSH_ERROR) {
      log_entry ("FATAL: ssh_bind_accept(): %s", ssh_get_error (sshbind));
      exit (EXIT_FAILURE);
    }

    child = fork();

    if (child < 0) {
      log_entry ("FATAL: fork(): %s", strerror (errno));
      exit (EXIT_FAILURE);
    }

    if (child == 0) {
      exit (handle_ssh_auth (session));
    }
  }

  return EXIT_SUCCESS;
}
