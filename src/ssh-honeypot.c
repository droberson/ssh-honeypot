/* ssh-honeypot -- by Daniel Roberson (daniel(a)planethacker.net) 2016-2019
 *
 * TODO: keep fp open for log_entry; reload on HUP
 * TODO: hassh?
 * TODO: add more banners
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <libssh/libssh.h>
#include <libssh/server.h>

#include <json-c/json.h>

#include "config.h"


/* banners */
static struct banner_info_s {
  const char	*str, *info;
} banners[] = {
  {"",  "No banner"},
  {"OpenSSH_5.9p1 Debian-5ubuntu1.4", "Ubuntu 12.04"},
  {"OpenSSH_7.2p2 Ubuntu-4ubuntu2.1", "Ubuntu 16.04"},
  {"OpenSSH_6.6.1",                   "openSUSE 42.1"},
  {"OpenSSH_6.7p1 Debian-5+deb8u3",   "Debian 8.6"}
};

const size_t num_banners = sizeof banners / sizeof *banners;


/* Globals */
char *          logfile = LOGFILE;
char *          pidfile = PIDFILE;
char *          rsakey = RSAKEY;
char *          bindaddr = BINDADDR;
bool            console_output = true;
bool            daemonize = false;
bool            use_syslog = false;
bool            json_logging_file = false;
bool            json_logging_server = false;
char *          json_logfile = JSON_LOGFILE;
char *          json_server = JSON_SERVER;
unsigned short  json_port = JSON_PORT;
int             json_sock;


/* usage() -- prints out usage instructions and exits the program
 */
static void usage (const char *progname) {
  fprintf (stderr, "ssh-honeypot %s by %s\n\n", VERSION, AUTHOR);

  fprintf (stderr, "usage: %s "
	   "[-?h -p <port> -a <address> -b <index> -l <file> -r <file> "
	   "-f <file> -u <user>]\n",
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
  fprintf (stderr, "\t-u <user>\t-- user to setuid() to after bind()\n");
  fprintf (stderr, "\t-j <file>\t-- path to JSON logfile\n");
  fprintf (stderr, "\t-J <address>\t-- server to send JSON logs\n");
  fprintf (stderr, "\t-P <port>\t-- port to send JSON logs\n");

  exit (EXIT_FAILURE);
}


/* pr_banners() -- prints out a list of available banner options
 */
static void pr_banners () {
  size_t	i;

  fprintf (stderr, "Available banners: [index] banner (description)\n");

  for (i = 0; i < num_banners; i++) {
    struct banner_info_s *banner = banners + i;
    fprintf (stderr, "[%zu] %s (%s)\n", i, banner->str, banner->info);
  }

  fprintf (stderr, "Total banners: %zu\n", num_banners);
}


/* sockprintf() -- send formatted data to a socket
 */
static int sockprintf (int s, const char *fmt, ...) {
  int           n;
  char          buf[8192] = {0};
  va_list       vl;

  va_start (vl, fmt);
  n = vsnprintf (buf, sizeof(buf), fmt, vl);
  va_end (vl);

  return send (s, buf, n, 0);
}

/* log_entry() -- adds timestamped log entry
 *             -- displays output to stdout if console_output is true
 *             -- returns 0 on success, 1 on failure
 */
static int log_entry (const char *fmt, ...) {
  int		n;
  FILE *	fp;
  time_t	t;
  va_list	va;
  char *	timestr;
  char		buf[1024];


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
  vsnprintf (buf, sizeof(buf), fmt, va);
  va_end (va);

  if (use_syslog)
    syslog (LOG_INFO | LOG_AUTHPRIV, "%s", buf);

  n = fprintf (fp, "[%s] %s\n", timestr, buf);

  if (console_output)
    printf ("[%s] %s\n", timestr, buf);

  fclose (fp);
  return n;
}


/* json_log() -- log JSON formatted data to a file
 */
static void json_log (const char *msg) {
  FILE *	fp;

  fp = fopen (json_logfile, "a");

  if (fp == NULL) {
    log_entry ("FATAL: Unable to open JSON log file %s: %s\n",
	       json_logfile,
	       strerror (errno));

    exit (EXIT_FAILURE);
  }

  fprintf (fp, "%s\n", msg);
  fclose (fp);
}


/* json_log_creds() -- log username/password in JSON format
 */
static void json_log_creds (const char *ip, const char *user, const char *pass) {
  char *        message;
  json_object   *jobj    = json_object_new_object ();
  json_object   *j_time  = json_object_new_int (time(NULL));
  json_object   *j_host  = json_object_new_string (ip);
  json_object   *j_user  = json_object_new_string (user);
  json_object   *j_pass  = json_object_new_string (pass);
  json_object   *j_event = json_object_new_string ("ssh-honeypot-auth");

  json_object_object_add (jobj, "event", j_event);
  json_object_object_add (jobj, "time", j_time);
  json_object_object_add (jobj, "host", j_host);
  json_object_object_add (jobj, "user", j_user);
  json_object_object_add (jobj, "pass", j_pass);

  message = (char *)json_object_to_json_string (jobj);

  if (json_logging_file)
    json_log (message);

  if (json_logging_server)
    sockprintf (json_sock, "%s\r\n", message);

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

  if (json_logging_server) {
    struct sockaddr_in  s_addr;
    json_sock = socket (AF_INET, SOCK_DGRAM, 0);
    if (json_sock < 0) {
      log_entry ("FATAL: socket(): %s\n", strerror (errno));
      exit (EXIT_FAILURE);
    }

    bzero (&s_addr, sizeof(s_addr));
    s_addr.sin_family = AF_INET;
    s_addr.sin_addr.s_addr = inet_addr (json_server);
    s_addr.sin_port = htons (json_port);

    /* connect() UDP socket to avoid sendto() */
    if (connect (json_sock, (struct sockaddr *)&s_addr, sizeof(s_addr)) == -1) {
      log_entry ("FATAL: connect(): %s\n", strerror (errno));
      exit (EXIT_FAILURE);
    }
  }

  signal (SIGCHLD, SIG_IGN);

  if (daemonize) {
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

    if (daemonize)
      printf ("FATAL: ssh_bind_listen(): %s\n", ssh_get_error (sshbind));

    exit (EXIT_FAILURE);
  }

  /* drop privileges */
  if (username != NULL)
    drop_privileges (username);

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
