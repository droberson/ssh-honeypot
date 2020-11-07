/* ssh-honeypot -- by Daniel Roberson (daniel(a)planethacker.net) 2016-2019
 *
 * TODO: keep fp open for log_entry; reload on HUP
 * TODO: config files
 * TODO: hassh?
 *       i don't see a way to do this right now. from what ive gathered,
 *       libssh doesn't provide an easy way to look at the ssh handshake
 *       packets and see the full list of kex methods, crypto methods,
 *       compression, ...
 *       Thought about modifying the library to just do hassh in there,
 *       trying something with libpcap, or writing another tool altogether.
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
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <libssh/libssh.h>
#include <libssh/server.h>

#include <json-c/json.h>

#include "config.h"


/* Globals */
char *          logfile             = LOGFILE;
char *          pidfile             = PIDFILE;
char *          rsakey              = RSAKEY;
char *          bindaddr            = BINDADDR;
bool            console_output      = true;
bool            daemonize           = false;
bool            use_syslog          = false;
bool            logging             = true;
bool            json_logging_file   = false;
bool            json_logging_server = false;
char *          json_logfile        = JSON_LOGFILE;
char *          json_server         = JSON_SERVER;
unsigned short  json_port           = JSON_PORT;
bool            verbose             = false;
int             json_sock;
char            hostname[MAXHOSTNAMELEN];


/* Banners */
static struct banner_info_s {
  const char	*str, *info;
} banners[] = {
  {"",  "No banner"},
  {"OpenSSH_5.9p1 Debian-5ubuntu1.4", "Ubuntu 12.04"},
  {"OpenSSH_7.2p2 Ubuntu-4ubuntu2.1", "Ubuntu 16.04"},
  {"OpenSSH_7.6p1 Ubuntu-4ubuntu0.3", "Ubuntu 18.04"},
  {"OpenSSH_6.6.1",                   "openSUSE 42.1"},
  {"OpenSSH_6.7p1 Debian-5+deb8u3",   "Debian 8.6"},
  {"OpenSSH_7.5",                     "pfSense 2.4.4-RELEASE-p3"},
  {"dropbear_2014.63",                "dropbear 2014.63"},
};

const size_t num_banners = sizeof banners / sizeof *banners;


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
  fprintf (stderr, "\t-d\t\t-- Daemonize process\n");
  fprintf (stderr, "\t-f\t\t-- PID file\n");
  fprintf (stderr, "\t-L\t\t-- toggle logging to a file. Default: %s\n",
           logging ? "on" : "off");
  fprintf (stderr, "\t-l <file>\t-- log file\n");
  fprintf (stderr, "\t-s\t\t-- toggle syslog usage. Default: %s\n",
	   use_syslog ? "on" : "off");
  fprintf (stderr, "\t-r <file>\t-- specify RSA key to use\n");
  fprintf (stderr, "\t-f <file>\t-- specify location to PID file\n");
  fprintf (stderr, "\t-b\t\t-- list available banners\n");
  fprintf (stderr, "\t-b <string>\t-- specify banner string (max 255 characters)\n");
  fprintf (stderr, "\t-i <index>\t-- specify banner index\n");
  fprintf (stderr, "\t-u <user>\t-- user to setuid() to after bind()\n");
  fprintf (stderr, "\t-j <file>\t-- path to JSON logfile\n");
  fprintf (stderr, "\t-J <address>\t-- server to send JSON logs\n");
  fprintf (stderr, "\t-P <port>\t-- port to send JSON logs\n");
  fprintf (stderr, "\t-v\t-- verbose log output\n");

  exit (EXIT_FAILURE);
}


/* pr_banners() -- prints out a list of available banner options
 */
static void pr_banners () {
  fprintf (stderr, "Available banners: [index] banner (description)\n");

  for (size_t i = 0; i < num_banners; i++) {
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
 */
static void log_entry (const char *fmt, ...) {
  FILE *	fp;
  time_t	t;
  va_list	va;
  char *	timestr;
  char		buf[1024];


  time (&t);
  timestr = strtok (ctime (&t), "\n"); // banish newline character to the land
                                       // of wind and ghosts

  va_start (va, fmt);
  vsnprintf (buf, sizeof(buf), fmt, va);
  va_end (va);

  if (logging) {
    if ((fp = fopen (logfile, "a+")) == NULL) {
      fprintf (stderr, "Unable to open logfile %s: %s\n",
	       logfile,
	       strerror (errno));
    } else {
      fprintf (fp, "[%s] %s\n", timestr, buf);
      fclose (fp);
    }
  }

  if (use_syslog)
    syslog (LOG_INFO | LOG_AUTHPRIV, "%s", buf);

  if (console_output)
    printf ("[%s] %s\n", timestr, buf);
}


/* log_entry_fatal() -- log a message, then exit with EXIT_FAILURE
 */
void log_entry_fatal (const char *fmt, ...) {
  va_list       vl;

  va_start (vl, fmt);
  log_entry (fmt, vl);
  va_end (vl);

  exit (EXIT_FAILURE);
}


/* json_log() -- log JSON formatted data to a file
 */
static void json_log (const char *msg) {
  FILE *	fp;

  fp = fopen (json_logfile, "a");

  if (fp == NULL)
    log_entry_fatal ("FATAL: Unable to open JSON log file %s: %s\n",
	       json_logfile,
	       strerror (errno));

  fprintf (fp, "%s\n", msg);
  fclose (fp);
}


/* json_log_creds() -- log username/password in JSON format
 */
static void json_log_creds (const char *ip, const char *user, const char *pass) {
  char *        message;
  json_object   *jobj     = json_object_new_object ();
  json_object   *j_time   = json_object_new_int (time(NULL));
  json_object   *j_host   = json_object_new_string (hostname);
  json_object   *j_client = json_object_new_string (ip);
  json_object   *j_user   = json_object_new_string (user);
  json_object   *j_pass   = json_object_new_string (pass);
  json_object   *j_event  = json_object_new_string ("ssh-honeypot-auth");

  json_object_object_add (jobj, "event", j_event);
  json_object_object_add (jobj, "time", j_time);
  json_object_object_add (jobj, "host", j_host);
  json_object_object_add (jobj, "client", j_client);
  json_object_object_add (jobj, "user", j_user);
  json_object_object_add (jobj, "pass", j_pass);

  message = (char *)json_object_to_json_string (jobj);

  if (json_logging_file)
    json_log (message);

  if (json_logging_server)
    sockprintf (json_sock, "%s\r\n", message);

  json_object_put (jobj);
}


/* json_log_kex_error() -- log connections in JSON format
 */
static void json_log_kex_error (const char *ip) {
  char *        message;
  json_object   *jobj     = json_object_new_object ();
  json_object   *j_time   = json_object_new_int (time (NULL));
  json_object   *j_host   = json_object_new_string (hostname);
  json_object   *j_client = json_object_new_string (ip);
  json_object   *j_event  = json_object_new_string ("ssh-honetpot-kexerror");

  json_object_object_add (jobj, "event", j_event);
  json_object_object_add (jobj, "time", j_time);
  json_object_object_add (jobj, "host", j_host);
  json_object_object_add (jobj, "client", j_client);

  message = (char *)json_object_to_json_string (jobj);

  if (json_logging_file)
    json_log (message);

  if (json_logging_server)
    sockprintf (json_sock, "%s\r\n", message);

  json_object_put (jobj);
}


/* json_log_session() - log information about client sessions
 */
static void json_log_session (const char *client_ip,
			      const char *banner_c,
			      const char *banner_s,
			      const char *kex_algo,
			      const char *cipher_in,
			      const char *cipher_out,
			      const char *hmac_in,
			      const char *hmac_out) {
  char *        message;
  json_object  *jobj         = json_object_new_object ();
  json_object  *j_time       = json_object_new_int (time (NULL));
  json_object  *j_host       = json_object_new_string (hostname);
  json_object  *j_client     = json_object_new_string (client_ip);
  json_object  *j_event      = json_object_new_string ("ssh-honeypot-session");
  json_object  *j_banner_c   = json_object_new_string (banner_c);
  json_object  *j_banner_s   = json_object_new_string (banner_s);
  json_object  *j_kex_algo   = json_object_new_string (kex_algo);
  json_object  *j_cipher_in  = json_object_new_string (cipher_in);
  json_object  *j_cipher_out = json_object_new_string (cipher_out);
  json_object  *j_hmac_in    = json_object_new_string (hmac_in);
  json_object  *j_hmac_out   = json_object_new_string (hmac_out);

  json_object_object_add (jobj, "event", j_event);
  json_object_object_add (jobj, "time", j_time);
  json_object_object_add (jobj, "host", j_host);
  json_object_object_add (jobj, "client", j_client);
  json_object_object_add (jobj, "client_banner", j_banner_c);
  json_object_object_add (jobj, "server_banner", j_banner_s);
  json_object_object_add (jobj, "kex_algo", j_kex_algo);
  json_object_object_add (jobj, "cipher_in", j_cipher_in);
  json_object_object_add (jobj, "cipher_out", j_cipher_out);
  json_object_object_add (jobj, "hmac_in", j_hmac_in);
  json_object_object_add (jobj, "hmac_out", j_hmac_out);

  message = (char *)json_object_to_json_string (jobj);

  if (json_logging_file)
    json_log (message);

  if (json_logging_server)
    sockprintf (json_sock, "%s\r\n", message);

  json_object_put (jobj);
}


/* get_ssh_ip() -- obtains IP address via ssh_session
 */
static char *get_ssh_ip (ssh_session session) {
  static char			ip[INET6_ADDRSTRLEN];
  struct sockaddr_storage	tmp;
  struct in_addr		*inaddr;
  struct in6_addr		*in6addr;
  socklen_t			address_len = sizeof(tmp);


  getpeername (ssh_get_fd (session), (struct sockaddr *)&tmp, &address_len);
  inaddr = &((struct sockaddr_in *)&tmp)->sin_addr;
  in6addr = &((struct sockaddr_in6 *)&tmp)->sin6_addr;
  inet_ntop (tmp.ss_family, tmp.ss_family==AF_INET?(void*)inaddr:(void*)in6addr,
	     ip, sizeof(ip));

  return ip;
}


/* handle_ssh_auth() -- handles ssh authentication requests, logging
 *                   -- appropriately.
 */
static int handle_ssh_auth (ssh_session session) {
  ssh_message	message;
  char *	ip;


  ip = get_ssh_ip (session);

  if (ssh_handle_key_exchange (session)) {
    if (verbose)
      log_entry ("%s Error exchanging keys: %s", ip, ssh_get_error (session));

    if (json_logging_file || json_logging_server)
      json_log_kex_error (ip);

    return -1;
  }

  char *banner_c   = (char *)ssh_get_clientbanner (session);
  char *banner_s   = (char *)ssh_get_serverbanner (session);
  char *kex_algo   = (char *)ssh_get_kex_algo (session);
  char *cipher_in  = (char *)ssh_get_cipher_in (session);
  char *cipher_out = (char *)ssh_get_cipher_out (session);
  char *hmac_in    = (char *)ssh_get_hmac_in (session);
  char *hmac_out   = (char *)ssh_get_hmac_out (session);

  if (json_logging_file || json_logging_server)
    json_log_session (ip,
		      banner_c,
		      banner_s,
		      ssh_get_kex_algo (session),
		      ssh_get_cipher_in (session),
		      ssh_get_cipher_out (session),
		      ssh_get_hmac_in (session),
		      ssh_get_hmac_out (session));

  if (verbose)
    log_entry ("Session:  %s|%s|%s|%s|%s|%s|%s",
  	     banner_c,
  	     banner_s,
  	     kex_algo,
  	     cipher_in,
  	     cipher_out,
  	     hmac_in,
  	     hmac_out);

  for (;;) {
    if ((message = ssh_message_get (session)) == NULL)
      break;

    switch (ssh_message_subtype (message)) {
    case SSH_AUTH_METHOD_PASSWORD:
      if (json_logging_file || json_logging_server)
	json_log_creds (ip,
			ssh_message_auth_user (message),
			ssh_message_auth_password (message));

      log_entry ("%s %s %s",
		 ip,
		 ssh_message_auth_user (message),
		 ssh_message_auth_password (message));
      break;

    default:
      break;
      printf("other: %d\n", ssh_message_subtype (message));
    }

    ssh_message_reply_default (message);
    ssh_message_free (message);
  }

  return 0;
}


/* write_pid_file() -- writes PID to PIDFILE
 */
static void write_pid_file (char *path, pid_t pid) {
  FILE *	fp;

  fp = fopen (path, "w");

  if (fp == NULL)
    log_entry_fatal ("FATAL: Unable to open PID file %s: %s\n",
		     path,
		     strerror (errno));

  fprintf (fp, "%d", pid);
  fclose (fp);
}


/* drop_privileges() -- drops privileges to specified user/group
 */
void drop_privileges (char *username) {
  struct passwd *	pw;
  struct group *	grp;


  pw = getpwnam (username);
  if (pw == NULL)
    log_entry_fatal ("FATAL: Username does not exist: %s\n", username);

  grp = getgrgid (pw->pw_gid);
  if (grp == NULL)
    log_entry_fatal ("FATAL: Unable to determine groupfor %d: %s\n",
		     pw->pw_gid,
		     strerror (errno));

  /* chown logfile so this user can use it */
  if (chown (logfile, pw->pw_uid, pw->pw_gid) == -1)
    log_entry_fatal ("FATAL: Unable to set permissions for log file %s: %s\n",
		     logfile,
		     strerror (errno));

  /* drop group first */
  if (setgid (pw->pw_gid) == -1)
    log_entry_fatal ("FATAL: Unable to drop group permissions to %s: %s\n",
		     grp->gr_name,
		     strerror (errno));

  /* drop user privileges */
  if (setuid (pw->pw_uid) == -1)
    log_entry_fatal ("FATAL: Unable to drop user permissions to %s: %s\n",
		     username,
		     strerror (errno));
}


/* main() -- main entry point of program
 */
int main (int argc, char *argv[]) {
  pid_t			pid, child;
  int			opt;
  unsigned short	port = PORT, banner_index = 1;
  const char *		banner = banners[1].str;
  char *		username = NULL;
  ssh_session		session;
  ssh_bind		sshbind;


  while ((opt = getopt (argc, argv, "vh?p:dLl:a:b:i:r:f:su:j:J:P:")) != -1) {
    switch (opt) {
    case 'p': /* Listen port */
      port = atoi(optarg);
      break;

    case 'd': /* Daemonize */
      daemonize = true;
      console_output = false;
      break;

    case 'L': /* Toggle logging to a file */
      logging = logging ? false : true;
      break;

    case 'l': /* Log file path */
      logfile = optarg;
      break;

    case 'a': /* IP to bind to */
      bindaddr = optarg;
      break;

    case 'r': /* Path to RSA key */
      rsakey = optarg;
      break;

    case 'f': /* PID file location */
      pidfile = optarg;
      break;

    case 's': /* Toggle syslog */
      use_syslog = use_syslog ? false : true;
      break;

    case 'u': /* User to drop privileges to */
      username = optarg;
      break;

    case 'i': /* Set banner by index */
      banner_index = atoi(optarg);

      if (banner_index >= num_banners) {
          fprintf (stderr, "FATAL: Invalid banner index\n");
          exit (EXIT_FAILURE);
      }

      banner = banners[banner_index].str;
      break;

    case 'b': /* Specify banner string */
      banner = optarg;
      break;

    case 'j': /* JSON logfile */
      json_logging_file = true;
      json_logfile = optarg;
      break;

    case 'J': /* JSON server */
      json_logging_server = true;
      json_server = optarg;
      break;

    case 'P': /* JSON port */
      json_port = atoi(optarg);
      break;

    case '?': /* Print usage */
    case 'h':
      if (optopt == 'i' || optopt == 'b') {
        pr_banners();
        return EXIT_FAILURE;
      }
      usage (argv[0]);
      return EXIT_SUCCESS;

    case 'v': /* verbose output */
      verbose = true;
      break;

    default:
      usage (argv[0]);
    }
  }

  if (gethostname (hostname, sizeof(hostname)) == -1)
    log_entry_fatal ("FATAL: gethostname(): %s\n", strerror (errno));

  if (json_logging_server) {
    struct sockaddr_in  s_addr;

    json_sock = socket (AF_INET, SOCK_DGRAM, 0);
    if (json_sock < 0)
      log_entry_fatal ("FATAL: socket(): %s\n", strerror (errno));

    bzero (&s_addr, sizeof(s_addr));
    s_addr.sin_family = AF_INET;
    s_addr.sin_addr.s_addr = inet_addr (json_server);
    s_addr.sin_port = htons (json_port);

    /* connect() UDP socket to avoid sendto() */
    if (connect (json_sock, (struct sockaddr *)&s_addr, sizeof(s_addr)) == -1)
      log_entry_fatal ("FATAL: connect(): %s\n", strerror (errno));
  }

  signal (SIGCHLD, SIG_IGN);

  if (daemonize) {
    pid = fork();

    if (pid < 0)
      log_entry_fatal ("FATAL: fork(): %s\n", strerror (errno));

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
    if (daemonize)
      printf ("FATAL: ssh_bind_listen(): %s\n", ssh_get_error (sshbind));

    log_entry_fatal ("FATAL: ssh_bind_listen(): %s", ssh_get_error (sshbind));
  }

  /* drop privileges */
  if (username != NULL)
    drop_privileges (username);

  for (;;) {
    if (ssh_bind_accept (sshbind, session) == SSH_ERROR)
      log_entry_fatal ("FATAL: ssh_bind_accept(): %s", ssh_get_error (sshbind));

    child = fork();

    if (child < 0)
      log_entry_fatal ("FATAL: fork(): %s", strerror (errno));

    if (child == 0)
      exit (handle_ssh_auth (session));
  }

  return EXIT_SUCCESS;
}
