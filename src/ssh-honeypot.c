/* ssh-honeypot -- by Daniel Roberson (daniel(a)planethacker.net) 2016-2022
 *
 * TODO: keep fp open for log_entry; reload on HUP
 * TODO: config files
 * TODO: add more banners
 * TODO: log public keys.
 *       https://github.com/jeroen/libssh/blob/master/examples/ssh_server_fork.c
 * TODO: ipv6
 * TODO: do not print non-printable characters in usernames/passwords.
 */

#include <stdio.h>
#include <ctype.h>
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

/* needed for HASSH */
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <openssl/md5.h>

#include "config.h"


/* Globals */
char           *logfile             = LOGFILE;
char           *pidfile             = PIDFILE;
char           *rsakey              = RSAKEY;
char           *bindaddr            = BINDADDR;
uint16_t		port         		= PORT;
bool            console_output      = true;
bool            daemonize           = false;
bool            use_syslog          = false;
bool            logging             = true;
bool            json_logging_file   = false;
bool            json_logging_server = false;
char           *json_logfile        = JSON_LOGFILE;
char           *json_server         = JSON_SERVER;
unsigned short  json_port           = JSON_PORT;
bool            verbose             = false;
int             json_sock;
char            hostname[MAXHOSTNAMELEN];

bool			hassh_server		= false;


/* Banners */
static struct banner_info_s {
	const char	*str, *info;
} banners[] = {
	{"",  "No banner"},
	{"OpenSSH_5.9p1 Debian-5ubuntu1.4", "Ubuntu 12.04"},
	{"OpenSSH_7.2p2 Ubuntu-4ubuntu2.1", "Ubuntu 16.04"},
	{"OpenSSH_7.6p1 Ubuntu-4ubuntu0.3", "Ubuntu 18.04"},
	{"OpenSSH_8.2p1 Ubuntu-4ubuntu0.4", "Ubuntu 20.04"},
	{"OpenSSH_6.6.1",                   "openSUSE 42.1"},
	{"OpenSSH_6.7p1 Debian-5+deb8u3",   "Debian 8.6"},
	{"OpenSSH_7.5",                     "pfSense 2.4.4-RELEASE-p3"},
	{"dropbear_2014.63",                "dropbear 2014.63"},
	{"OpenSSH_6.7p1 Raspbian-5+deb8u4", "Rapberry Pi"},
	{"ROSSSH",                          "MikroTik"},
};

const size_t num_banners = sizeof(banners) / sizeof(*banners);


/* usage() -- prints out usage instructions and exits the program
 */
static void usage(const char *progname) {
	fprintf(stderr, "ssh-honeypot %s\n\n", VERSION);
	//TODO check make sure all of this actually jives with reality.
	fprintf(stderr, "usage: %s "
			"[-?h -p <port> -a <address> -b <index> -l <file> -r <file> "
			"-f <file> -u <user>]\n",
			progname);
	fprintf(stderr, "\t-?/-h\t\t-- this help menu\n");
	fprintf(stderr, "\t-p <port>\t-- listen port\n");
	fprintf(stderr, "\t-a <address>\t-- IP address to bind to\n");
	fprintf(stderr, "\t-d\t\t-- daemonize process\n");
	fprintf(stderr, "\t-f\t\t-- PID file\n");
	fprintf(stderr, "\t-L\t\t-- toggle logging to a file. Default: %s\n",
			logging ? "on" : "off");
	fprintf(stderr, "\t-l <file>\t-- log file\n");
	fprintf(stderr, "\t-s\t\t-- toggle syslog usage. Default: %s\n",
			use_syslog ? "on" : "off");
	fprintf(stderr, "\t-t\t\t-- authentication timeout. Default: %d\n",
			TIMEOUT);
	fprintf(stderr, "\t-r <file>\t-- specify RSA key to use\n");
	fprintf(stderr, "\t-f <file>\t-- specify location to PID file\n");
	fprintf(stderr, "\t-b\t\t-- list available banners\n");
	fprintf(stderr, "\t-b <string>\t-- specify banner string (max 255 characters)\n");
	fprintf(stderr, "\t-i <index>\t-- specify banner index\n");
	fprintf(stderr, "\t-u <user>\t-- user to setuid() to after bind()\n");
	fprintf(stderr, "\t-j <file>\t-- path to JSON logfile\n");
	fprintf(stderr, "\t-J <address>\t-- server to send JSON logs\n");
	fprintf(stderr, "\t-P <port>\t-- port to send JSON logs\n");
	fprintf(stderr, "\t-v\t\t-- verbose log output\n");

	exit(EXIT_FAILURE);
}


/* pr_banners() -- prints out a list of available banner options
 */
static void pr_banners() {
	fprintf(stderr, "Available banners: [index] banner (description)\n");

	for (size_t i = 0; i < num_banners; i++) {
		struct banner_info_s	*banner = banners + i;
		fprintf(stderr, "[%zu] %s (%s)\n", i, banner->str, banner->info);
	}

	fprintf(stderr, "Total banners: %zu\n", num_banners);
}


/* sockprintf() -- send formatted data to a socket
 */
static int sockprintf(int s, const char *fmt, ...) {
	int		n;
	char		buf[8192] = {0};
	va_list	vl;

	va_start(vl, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, vl);
	va_end(vl);

	return send(s, buf, n, 0);
}


/* log_entry() -- adds timestamped log entry
 *             -- displays output to stdout if console_output is true
 */
static void log_entry(const char *fmt, ...) {
	FILE		*fp;
	time_t		t;
	va_list	va;
	char		*timestr;
	char		buf[1024];


	time(&t);
	timestr = strtok(ctime(&t), "\n"); // remove newline

	va_start(va, fmt);
	vsnprintf(buf, sizeof(buf), fmt, va);
	va_end(va);

	if (logging) {
		if ((fp = fopen(logfile, "a+")) == NULL) {
			fprintf(stderr, "Unable to open log file %s: %s\n", logfile, strerror(errno));
		} else {
			fprintf(fp, "[%s] %s\n", timestr, buf);
			fclose(fp);
		}
	}

	if (use_syslog)
		syslog(LOG_INFO | LOG_AUTHPRIV, "%s", buf);

	if (console_output)
		printf("[%s] %s\n", timestr, buf);
}


/* log_entry_fatal() -- log a message, then exit with EXIT_FAILURE
 */
void log_entry_fatal(const char *fmt, ...) {
	va_list	vl;

	va_start(vl, fmt);
	log_entry(fmt, vl);
	va_end(vl);

	exit(EXIT_FAILURE);
}


/* json_log() -- log JSON formatted data to a file
 */
static void json_log(const char *msg) {
	FILE	*fp;

	fp = fopen(json_logfile, "a");

	if (fp == NULL)
		log_entry_fatal("FATAL: Unable to open JSON log file %s: %s",
						json_logfile,
						strerror(errno));

	fprintf(fp, "%s\n", msg);
	fclose(fp);
}


/* json_log_creds() -- log username/password in JSON format
 */
static void json_log_creds(const char *ip, const char *user, const char *pass) {
	char			*message;

	json_object		*jobj     = json_object_new_object();
	json_object		*j_time   = json_object_new_int(time(NULL));
	json_object		*j_host   = json_object_new_string(hostname);
	json_object		*j_client = json_object_new_string(ip);
	json_object		*j_user   = json_object_new_string(user);
	json_object		*j_pass   = json_object_new_string(pass);
	json_object		*j_event  = json_object_new_string("ssh-honeypot-auth");

	json_object_object_add(jobj, "event", j_event);
	json_object_object_add(jobj, "time", j_time);
	json_object_object_add(jobj, "host", j_host);
	json_object_object_add(jobj, "client", j_client);
	json_object_object_add(jobj, "user", j_user);
	json_object_object_add(jobj, "pass", j_pass);

	message = (char *)json_object_to_json_string(jobj);

	if (json_logging_file)
		json_log(message);

	if (json_logging_server)
		sockprintf(json_sock, "%s\r\n", message);

	json_object_put(jobj);
}


/* json_log_hassh() - log HASSHes
 */
static void json_log_hassh(const char *hassh,
						   const char *ip,
						   const char *hassh_type,
						   const uint16_t sport,
						   const uint16_t ttl) {
	char			*message;

	json_object		*jobj    = json_object_new_object();
	json_object		*j_time  = json_object_new_int(time(NULL));
	json_object		*j_hassh = json_object_new_string(hassh);
	json_object		*j_ip    = json_object_new_string(ip);
	json_object		*j_sport = json_object_new_int(sport);
	json_object		*j_ttl   = json_object_new_int(ttl);
	json_object		*j_event = json_object_new_string(hassh_type);


	json_object_object_add(jobj, "event", j_event);
	json_object_object_add(jobj, "time", j_time);
	json_object_object_add(jobj, "ip", j_ip);
	json_object_object_add(jobj, "hassh", j_hassh);
	json_object_object_add(jobj, "sport", j_sport);
	json_object_object_add(jobj, "ttl", j_ttl);

	message = (char *)json_object_to_json_string(jobj);

	if (json_logging_file)
		json_log(message);

	if (json_logging_server)
		sockprintf(json_sock, "%s\r\n", message);

	json_object_put(jobj);
}


/* json_log_kex_error() -- log connections in JSON format
 */
static void json_log_kex_error(const char *ip) {
	char			*message;

	json_object		*jobj     = json_object_new_object();
	json_object		*j_time   = json_object_new_int(time(NULL));
	json_object		*j_host   = json_object_new_string(hostname);
	json_object		*j_client = json_object_new_string(ip);
	json_object		*j_event  = json_object_new_string("ssh-honetpot-kexerror");

	json_object_object_add(jobj, "event", j_event);
	json_object_object_add(jobj, "time", j_time);
	json_object_object_add(jobj, "host", j_host);
	json_object_object_add(jobj, "client", j_client);

	message = (char *)json_object_to_json_string(jobj);

	if (json_logging_file)
		json_log(message);

	if (json_logging_server)
		sockprintf(json_sock, "%s\r\n", message);

	json_object_put(jobj);
}


/* json_log_session() - log information about client sessions
 */
static void json_log_session(const char *client_ip,
							 const char *banner_c,
							 const char *banner_s,
							 const char *kex_algo,
							 const char *cipher_in,
							 const char *cipher_out,
							 const char *hmac_in,
							 const char *hmac_out) {
	char			*message;
	json_object	*jobj         = json_object_new_object();
	json_object	*j_time       = json_object_new_int(time(NULL));
	json_object	*j_host       = json_object_new_string(hostname);
	json_object	*j_client     = json_object_new_string(client_ip);
	json_object	*j_event      = json_object_new_string("ssh-honeypot-session");
	json_object	*j_banner_c   = json_object_new_string(banner_c);
	json_object	*j_banner_s   = json_object_new_string(banner_s);
	json_object	*j_kex_algo   = json_object_new_string(kex_algo);
	json_object	*j_cipher_in  = json_object_new_string(cipher_in);
	json_object	*j_cipher_out = json_object_new_string(cipher_out);
	json_object	*j_hmac_in    = json_object_new_string(hmac_in);
	json_object	*j_hmac_out   = json_object_new_string(hmac_out);

	json_object_object_add(jobj, "event", j_event);
	json_object_object_add(jobj, "time", j_time);
	json_object_object_add(jobj, "host", j_host);
	json_object_object_add(jobj, "client", j_client);
	json_object_object_add(jobj, "client_banner", j_banner_c);
	json_object_object_add(jobj, "server_banner", j_banner_s);
	json_object_object_add(jobj, "kex_algo", j_kex_algo);
	json_object_object_add(jobj, "cipher_in", j_cipher_in);
	json_object_object_add(jobj, "cipher_out", j_cipher_out);
	json_object_object_add(jobj, "hmac_in", j_hmac_in);
	json_object_object_add(jobj, "hmac_out", j_hmac_out);

	message = (char *)json_object_to_json_string(jobj);

	if (json_logging_file)
		json_log(message);

	if (json_logging_server)
		sockprintf(json_sock, "%s\r\n", message);

	json_object_put(jobj);
}


/* get_ssh_ip() -- obtains IP address via ssh_session
 */
static char *get_ssh_ip(ssh_session session) {
	static char					ip[INET6_ADDRSTRLEN];
	struct sockaddr_storage		tmp;
	struct in_addr				*inaddr;
	struct in6_addr				*in6addr;
	socklen_t					address_len = sizeof(tmp);


	getpeername(ssh_get_fd(session), (struct sockaddr *)&tmp, &address_len);
	inaddr = &((struct sockaddr_in *)&tmp)->sin_addr;
	in6addr = &((struct sockaddr_in6 *)&tmp)->sin6_addr;
	inet_ntop(tmp.ss_family,
			  tmp.ss_family == AF_INET ? (void*)inaddr : (void*)in6addr,
			  ip, sizeof(ip));

  return ip;
}


/* parse_hassh() -- parse packets, calculate HASSH
 */
void parse_hassh(u_char *args,
				  const struct pcap_pkthdr *header,
				  const u_char *packet) {
	uint32_t		kex_len;
	uint32_t		hka_len;
	uint32_t		e_ctos_len;
	uint32_t		e_stoc_len;
	uint32_t		mac_ctos_len;
	uint32_t		mac_stoc_len;
	uint32_t		compression_len;
	uint32_t		offset;

	uint8_t			kex_methods[2048]	= {0};
	uint8_t			e_ctos[2048] = {0};
	uint8_t			mac_ctos[2048] = {0};
	uint8_t			compression[2048] = {0};

	struct ip		*ip_header;
	struct tcphdr	*tcp_header;


	/* populate ip and tcphdr structures. set offset to start of data. */
	ip_header = (struct ip *)(packet);
	tcp_header = (struct tcphdr *)(packet + sizeof(struct ip));
	offset = sizeof(struct ip) + sizeof(struct tcphdr);

	/* Look for SSH2_MSG_KEXINIT packets */
	if (packet[offset + 5] != 0x14) // 0x14 == SSH2_MSG_KEXINIT
		return;

	/* Don't innundate logs with the server's HASSH. */
	if ((htons(tcp_header->th_sport) == port) && hassh_server)
		return;

	/* lol */
	offset += 25;
	if (header->len < offset)
		goto end;
	kex_len = (packet[offset - 3] << 24) | (packet[offset - 2] << 16) |
		(packet[offset - 1] << 8) | (packet[offset]);
	if (kex_len > sizeof(kex_methods))
		goto end;
	memcpy(kex_methods, &packet[offset + 1], kex_len);
	offset += 4 + kex_len;

	if (header->len < offset)
		goto end;
	hka_len = (packet[offset - 3] << 24) | (packet[offset - 2] << 16) |
		(packet[offset - 1] << 8) | (packet[offset]);
	offset += 4 + hka_len;

	if (header->len < offset)
		goto end;
	e_ctos_len = (packet[offset - 3] << 24) | (packet[offset - 2] << 16) |
		(packet[offset - 1] << 8) | (packet[offset]);
	if (e_ctos_len > sizeof(e_ctos))
		goto end;
	memcpy(e_ctos, &packet[offset + 1], e_ctos_len);
	offset += 4 + e_ctos_len;

	if (header->len < offset)
		goto end;
	e_stoc_len = (packet[offset - 3] << 24) | (packet[offset - 2] << 16) |
		(packet[offset - 1] << 8) | (packet[offset]);
	offset += 4 + e_stoc_len;

	if (header->len < offset)
		goto end;
	mac_ctos_len = (packet[offset - 3] << 24) | (packet[offset - 2] << 16) |
		(packet[offset - 1] << 8) | (packet[offset]);
	if (mac_ctos_len > sizeof(mac_ctos))
		goto end;
	memcpy(mac_ctos, &packet[offset + 1], mac_ctos_len);
	offset += 4 + mac_ctos_len;

	if (header->len < offset)
		goto end;
	mac_stoc_len = (packet[offset - 3] << 24) | (packet[offset - 2] << 16) |
		(packet[offset - 1] << 8) | (packet[offset]);
	offset += 4 + mac_stoc_len;

	if (header->len < offset)
		goto end;
	compression_len = (packet[offset - 3] << 24) | (packet[offset - 2] << 16) |
		(packet[offset - 1] << 8) | (packet[offset]);
	if (compression_len > sizeof(compression))
		goto end;
	memcpy(compression, &packet[offset + 1], compression_len);


	/* calculate HASSH */
    char hassh[8192];

	snprintf(hassh, sizeof(hassh), "%s;%s;%s;%s", kex_methods, e_ctos, mac_ctos, compression);

	uint8_t digest[16];
	char hassh_digest[33];

	MD5_CTX ctx;

	MD5_Init(&ctx);
	MD5_Update(&ctx, hassh, strlen(hassh));
	MD5_Final(digest, &ctx);

	snprintf(hassh_digest,
			 sizeof(hassh_digest),
			 "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			 digest[0],  digest[1],  digest[2],  digest[3],  digest[4],
			 digest[5],  digest[6],  digest[7],  digest[8],  digest[9],
			 digest[10], digest[11], digest[12], digest[13], digest[14],
			 digest[15]);

	/* Log and output */
	log_entry("%s: %s %s sport: %d ttl: %d",
			  htons(tcp_header->th_sport) == port ? "HASSHServer" : "HASSH",
			  inet_ntoa(ip_header->ip_src),
			  hassh_digest,
			  htons(tcp_header->th_sport),
			  ip_header->ip_ttl);

	if (json_logging_file || json_logging_server)
		json_log_hassh(hassh_digest,
					   inet_ntoa(ip_header->ip_src),
					   htons(tcp_header->th_sport) == port ?
					   "hasshserver" : "hassh",
					   htons(tcp_header->th_sport),
					   ip_header->ip_ttl);

	return;

 end:
	/* Something went wrong! Save pcap, hexdump packet. */

	printf("Shouldn't get here..\n\n");
}


/* handle_ssh_auth() -- handles ssh authentication requests, logging
 *                   -- appropriately.
 */
static int handle_ssh_auth(ssh_session session) {
	ssh_message		message;
	char			*ip;
	ssh_pcap_file	pcap;
	char			pcap_file[PATH_MAX];
	pcap_t			*pd;
	char			errbuf[PCAP_ERRBUF_SIZE];


	snprintf(pcap_file, sizeof(pcap_file), "/tmp/ssh-honeypot-%d.pcap", getpid());

	/* Create pcap file. Necessary to calculate HASSHes. */
	pcap = ssh_pcap_file_new();
	if (ssh_pcap_file_open(pcap, pcap_file) == SSH_ERROR) {
		log_entry("ERROR: Couldnt open pcap file %s: %s\n",
				  pcap_file, errbuf);
		ssh_pcap_file_free(pcap);
	} else {
		ssh_set_pcap_file(session, pcap);
	}

	ip = get_ssh_ip(session);

	if (ssh_handle_key_exchange(session)) {
		if (verbose)
			log_entry("%s Error exchanging keys: %s", ip, ssh_get_error (session));

		if (json_logging_file || json_logging_server)
			json_log_kex_error (ip);

		return -1;
	}

	// TODO log connections to ssh-honeypot.log/stdout?

	char *banner_c   = (char *)ssh_get_clientbanner(session);
	char *banner_s   = (char *)ssh_get_serverbanner(session);
	char *kex_algo   = (char *)ssh_get_kex_algo(session);
	char *cipher_in  = (char *)ssh_get_cipher_in(session);
	char *cipher_out = (char *)ssh_get_cipher_out(session);
	char *hmac_in    = (char *)ssh_get_hmac_in(session);
	char *hmac_out   = (char *)ssh_get_hmac_out(session);

	if (json_logging_file || json_logging_server)
		json_log_session(ip,
						 banner_c,
						 banner_s,
						 ssh_get_kex_algo(session),
						 ssh_get_cipher_in(session),
						 ssh_get_cipher_out(session),
						 ssh_get_hmac_in(session),
						 ssh_get_hmac_out(session));

	if (verbose)
		log_entry("Session:  %s|%s|%s|%s|%s|%s|%s",
				  banner_c,
				  banner_s,
				  kex_algo,
				  cipher_in,
				  cipher_out,
				  hmac_in,
				  hmac_out);

	for (;;) {
		if ((message = ssh_message_get(session)) == NULL)
			break;

		switch (ssh_message_subtype(message)) {
			// TODO SSH_AUTH_METHOD_PUBLICKEY
		case SSH_AUTH_METHOD_PASSWORD:
			if (json_logging_file || json_logging_server)
				json_log_creds(ip,
							   ssh_message_auth_user(message),
							   ssh_message_auth_password(message));

			log_entry("%s %s %s",
					  ip,
					  ssh_message_auth_user(message),
					  ssh_message_auth_password(message));
			break;

		default:
			break;
			printf("other: %d\n", ssh_message_subtype(message));
		}

		ssh_message_reply_default(message);
		ssh_message_free(message);
	}

	// TODO log end of session? elapsed time, ...

	/* Close pcap file when we're done with it. */
	ssh_pcap_file_free(pcap);

	/* Calculate HASSH */
	// TODO this appears to have been failing because the pcap
	//      wasn't being flushed before attempting to open/read the file.
	pd = pcap_open_offline(pcap_file, errbuf);
	if (pd == NULL) {
		log_entry("ERROR: Unable to open pcap file %s: %s",
				  pcap_file, errbuf);
		return 0;
	} else {
		pcap_loop(pd, 0, parse_hassh, NULL);
	}

	/* Remove packet capture file */
	unlink(pcap_file); // TODO error check

	return 0;
}


/* write_pid_file() -- writes PID to PIDFILE
 */
static void write_pid_file(char *path, pid_t pid) {
	FILE	*fp;

	fp = fopen(path, "w");

	if (fp == NULL)
		log_entry_fatal("FATAL: Unable to open PID file %s: %s\n",
						path,
						strerror(errno));

	fprintf(fp, "%d", pid);
	fclose(fp);
}


/* drop_privileges() -- drops privileges to specified user/group
 */
void drop_privileges(char *username) {
	struct passwd	*pw;
	struct group	*grp;


	pw = getpwnam(username);
	if (pw == NULL)
		log_entry_fatal("FATAL: Username does not exist: %s\n", username);

	grp = getgrgid(pw->pw_gid);
	if (grp == NULL)
		log_entry_fatal("FATAL: Unable to determine groupfor %d: %s\n",
						pw->pw_gid,
						strerror(errno));

	/* chown logfile so this user can use it */
	if (chown(logfile, pw->pw_uid, pw->pw_gid) == -1)
		log_entry_fatal("FATAL: Unable to set permissions for log file %s: %s\n",
						logfile,
						strerror(errno));

	/* drop group first */
	if (setgid(pw->pw_gid) == -1)
		log_entry_fatal("FATAL: Unable to drop group permissions to %s: %s\n",
						grp->gr_name,
						strerror(errno));

	/* drop user privileges */
	if (setuid (pw->pw_uid) == -1)
		log_entry_fatal("FATAL: Unable to drop user permissions to %s: %s\n",
						username,
						strerror(errno));
}


/* main() -- main entry point of program
 */
int main(int argc, char *argv[]) {
	pid_t			pid;
	pid_t			child;
	int				opt;
	unsigned short	banner_index = 1;
	const char		*banner      = banners[1].str;
	char			*username    = NULL;
	ssh_session		session;
	ssh_bind		sshbind;
	long			timeout      = TIMEOUT;


	while ((opt = getopt(argc, argv, "vh?p:dLl:a:b:i:r:f:su:j:J:P:")) != -1) {
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

		case 't': /* Authentication timeout */
			timeout = atoi(optarg);
			break;

		case 'u': /* User to drop privileges to */
			username = optarg;
			break;

		case 'i': /* Set banner by index */
			banner_index = atoi(optarg);

			if (banner_index >= num_banners) {
				fprintf(stderr, "FATAL: Invalid banner index\n");
				exit(EXIT_FAILURE);
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
			usage(argv[0]);
			return EXIT_SUCCESS;

		case 'v': /* verbose output */
			verbose = true;
			break;

		default:
			usage(argv[0]);
		}
	}

	if (gethostname(hostname, sizeof(hostname)) == -1)
		log_entry_fatal("FATAL: gethostname(): %s\n", strerror(errno));

	if (json_logging_server) {
		struct sockaddr_in	s_addr;

		json_sock = socket(AF_INET, SOCK_DGRAM, 0);
		if (json_sock < 0)
			log_entry_fatal("FATAL: socket(): %s\n", strerror(errno));

		bzero(&s_addr, sizeof(s_addr));
		s_addr.sin_family = AF_INET;
		s_addr.sin_addr.s_addr = inet_addr(json_server);
		s_addr.sin_port = htons(json_port);

		/* connect() UDP socket to avoid sendto() */
		if (connect(json_sock, (struct sockaddr *)&s_addr, sizeof(s_addr)) == -1)
			log_entry_fatal("FATAL: connect(): %s\n", strerror(errno));
	}

	signal(SIGCHLD, SIG_IGN);

	if (daemonize) {
		pid = fork();

		if (pid < 0)
			log_entry_fatal("FATAL: fork(): %s\n", strerror(errno));

		else if (pid > 0) {
			write_pid_file(pidfile, pid);
			exit(EXIT_SUCCESS);
		}

		printf("ssh-honeypot %s started on port %d. PID %d\n",
			   VERSION,
			   port,
			   getpid());
	}

	log_entry("ssh-honeypot %s started on port %d. PID %d",
			  VERSION,
			  port,
			  getpid());

	// https://github.com/droberson/ssh-honeypot/issues/21
	session = ssh_new();
	ssh_options_set(session, SSH_OPTIONS_TIMEOUT, (void *)&timeout);
	//ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY);

	sshbind = ssh_bind_new();

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, bindaddr);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BANNER, banner);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, rsakey);

	if (ssh_bind_listen(sshbind) < 0) {
		if (daemonize) // TODO: show meaningful error if key isn't supplied
			printf("FATAL: ssh_bind_listen(): %s\n", ssh_get_error(sshbind));

		log_entry_fatal("FATAL: ssh_bind_listen(): %s", ssh_get_error(sshbind));
	}

	/* drop privileges */
	if (username != NULL)
		drop_privileges(username);

	for (;;) {
		if (ssh_bind_accept(sshbind, session) == SSH_ERROR)
			log_entry_fatal("FATAL: ssh_bind_accept(): %s",
							ssh_get_error(sshbind));

		child = fork();

		if (child < 0)
			log_entry_fatal("FATAL: fork(): %s", strerror(errno));

		if (child == 0)
			exit(handle_ssh_auth(session));

		/* TODO: This may fail if the first connection to ssh-honeypot isn't
		   initiated by an ssh client. As a result, ssh-honeypot will never
           emit a hasshserver event.
		 */
		hassh_server = true;
	}

	return EXIT_SUCCESS;
}
