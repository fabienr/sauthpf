/*
 * Copyright (c) 2009 Denis Dechaux-Blanc <ded@asystant.net>
 * Copyright (c) 2009 Fabien Romano <fromano@asystant.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "../modules/compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <limits.h>

#include "../modules/conf.h"
#include "../modules/bdd.h"
#include "../modules/bool.h"
#include "../modules/fwl.h"
#include "../modules/log.h"
#include "../modules/users.h"
#include "../modules/sock.h"
#include "../modules/secure_auth.h"

#ifndef DEFAULT_CONF_FILE
#define DEFAULT_CONF_FILE "/etc/sauthpf.conf"
#endif

#define VERSION		"0.1"
#define SUBSYS		"sauthpf-daemon"

extern bool in_action;
extern bool end_process;

static void inline dameon_exec_actions(msg *, int);

void usage(void)
{
	printf(
		"exemple : \n"
		"\t-V : display version\n"
		"\t-v : Mode Verbose ON, display LOG_INFO\n"
		"\t-vv : Mode Verbose ON, display LOG_DEBUG\n"
		"\t-d : enable mode debug, write on stderr\n"
		"\t-f <file> : use this configuration file\n"
	);
	free_config();
	_exit(0);
}

void signal_handling(int sig)
{
	log(LOG_DEBUG, "signal_handling receive %d - quit", sig);
	if (in_action)
		end_process = true;
	else
		exit(1);
}

void clean_exit(void)
{
	close_socket_server();
	/* Close /dev/pf */
	fwl_quit();
	/* Close database */
	bdd_quit();
	/* Free config memory */
	free_config();
	/* Close log file */
	log(LOG_DEBUG, "Clean quit");
	log_quit();
}

int main(int argc, char **argv)
{
	char *file = NULL, ch;
	int sock_server = -1;
	int sock_client = -1;
	msg query;
	int verbose = 0;
	bool debug = false;

	/* Gestion des Signaux*/
	atexit(clean_exit);
	struct sigaction act;
	memset(&act,0,sizeof(act));
	act.sa_handler = signal_handling;
	if (sigaction(SIGINT,&act,NULL) == -1) {
		log(LOG_WARNING,"sigaction error %m");
		goto error;
	}
	if (sigaction(SIGTERM,&act,NULL) == -1) {
		log(LOG_WARNING,"sigaction error %m");
		goto error;
	}
	/*.....................*/

	while ((ch = getopt(argc, argv, "Vvdf:")) != EOF)
		switch (ch) {
		case 'V':
			fprintf(stderr, "exemple: %s\n", VERSION);
			exit(0);
			break;
		case 'v':
			if (verbose == 0) {
				fprintf(stderr,"Mode verbose ON\n");
				verbose = 1;
			}
			else if (verbose == 1) {
				fprintf(stderr,"Mode verbose ON and log level ="
				    " LOG_DEBUG\n");
				verbose = 2;
			}
			else
				usage();
			break;
		case 'd':
			fprintf(stderr,"Mode Debug ON\n");
			debug = true;
		break;
		case 'f':
			file = optarg;
			break;
		default:
			usage();
		}
	if (file == NULL)
		file = DEFAULT_CONF_FILE;

	log_init(SUBSYS, verbose, debug);
	log(LOG_DEBUG, "start daemon using configuration file '%s'", file);

	if (load_config(file) != 0) {
		log(LOG_WARNING, "load_config error");
		goto error;
	}

	if (fwl_init() != 0) {
		log(LOG_WARNING, "fwl_init error");
		goto error;
	}

	/* pid file write */
	if (conf_pid_path) {
		char *str;
		char *pid_file = NULL;
		pid_t pid, exist_pid;
		FILE * f;
		unsigned int size, wsize;

		pid = getpid();
		pid_file = file_get_contents(conf_pid_path);

		if (pid_file != NULL &&
		    !kill((exist_pid = atoi(pid_file)), 0)) {
			log(LOG_INFO, "Daemon already run");
			free(pid_file);
			goto error;
		}
		else {
			if (pid_file != NULL) {
				log(LOG_DEBUG, "remove conf_pid_path");
				remove(conf_pid_path);
			}
			else {
				log(LOG_DEBUG, "conf_pid_path isn't present");
			}
			if (!(size = asprintf(&str, "%d", pid))) {
				log(LOG_WARNING, "asprintf error : %m");
				goto error;
			}
			if (!(f = fopen(conf_pid_path, "w"))) {
				log(LOG_WARNING, "can't open '%s', open error "
				": %m", conf_pid_path);
			}
			else if ((wsize = fwrite(str, 1, size, f)) != size) {
				log(LOG_WARNING, "can't write %d byte, only %d "
				    "written on '%s', fwrite error : %m", size,
				    wsize, conf_pid_path);
			}
			else {
				log(LOG_DEBUG, "write pid %d on '%s'",
				    pid, conf_pid_path);
				fclose(f);
			}
		}
		free(pid_file);
		free(str);
	}

	if ((sock_server = socket_server(conf_socket_path)) == -1) {
		log(LOG_WARNING, "socket_server error");
		goto error;
	}

	if (change_rights() != 0) {
		log(LOG_WARNING, "change_rights error");
		goto error;
	}

	while (!end_process) {
		memset(&query, 0, sizeof(msg));
		if ((sock_client = sock_read_query(sock_server, &query)) >= 0) {
			dameon_exec_actions(&query, sock_client);
		}
		if (sock_client >= 0) {
			close(sock_client);
		}
	}
	if (sock_server >= 0) {
		close(sock_server);
	}

	/* Close /dev/fwl */
	fwl_quit();
	/* Close database */
	bdd_quit();
	/* Free config memory */
	free_config();
	/* Close log file */
	log(LOG_DEBUG, "nice quit");
	log_quit();
	_exit(0);
error:
	if (sock_client >= 0)
		close(sock_client);
	if (sock_server)
		close(sock_server >= 0);
	/* Close /dev/fwl */
	fwl_quit();
	/* Close database */
	bdd_quit();
	/* Free config memory */
	free_config();
	/* Close log file */
	log_quit();
	_exit(1);
}

static void inline dameon_exec_actions(msg *query, int sock_client)
{
	session *session_query = NULL, *current = NULL;
	char *err_msg = NULL;
	switch (query->op) {
	case OP_AUTH:
		if (*query->data.auth.password) {
			if (sauth(query->data.auth.user,
			    query->data.auth.password) == 1) {
				memset(query->data.auth.password, 0, PROTO_AUTH_STR_SIZE);
				asprintf(&err_msg, "auth_userokay "
				    "error");
				sock_send_reply(sock_client, REPLY_ERROR,
				    "auth error user: %s with ip : %s "
				    ": %s", query->data.auth.user,
				    query->data.auth.ip, err_msg);
				break;
			}
			memset(query->data.auth.password, 0, PROTO_AUTH_STR_SIZE);
		}
		else if (conf_secure_auth == true) {
			log(LOG_WARNING, "Sauth is enable but password "
			    "is missing");
			sock_send_reply(sock_client, REPLY_ERROR, "auth"
			    " error user: %s with ip : %s : %s",
			    query->data.auth.user, query->data.auth.ip,
			    err_msg);
			break;
		}
		if (!(session_query = auth(query->data.auth.user,
		    query->data.auth.ip, NULL, mode_direct, &err_msg))) {
			log(LOG_INFO, "function auth error: %s", err_msg);
			sock_send_reply(sock_client, REPLY_ERROR, "auth error "
			    "user: %s with ip : %s : %s", query->data.auth.user,
			    query->data.auth.ip, err_msg);
		}
		else {
			sock_send_msg_auth(sock_client, session_query);
			sock_send_reply(sock_client, REPLY_OK, "successful auth "
			    "user: %s with ip : %s", query->data.auth.user,
			    query->data.auth.ip);
			log(LOG_INFO, "successful auth user: %s with ip : %s",
			    query->data.auth.user, query->data.auth.ip);
		}
	break;
	case OP_UNAUTH:
		if (!(session_query = unauth(query->data.unauth.flag,
		    query->data.unauth.user_or_ip, mode_direct, &err_msg))) {

			log(LOG_INFO, "function unauth error: %s", err_msg);
			if (query->data.unauth.flag == by_user) {
				sock_send_reply(sock_client, REPLY_ERROR,
				    "unauth error user: %s : %s",
				    query->data.unauth.user_or_ip, err_msg);
			}
			else if (query->data.unauth.flag == by_ip) {
				sock_send_reply(sock_client, REPLY_ERROR,
				    "unauth error ip: %s : %s",
				    query->data.unauth.user_or_ip, err_msg);
			}
			else {
				sock_send_reply(sock_client, REPLY_ERROR,
				    "Invalid flag: %s", err_msg);
			}
		}
		else {
			if (!session_query->head) {
				sock_send_msg_auth(sock_client, session_query);
				log(LOG_INFO, "successful unauth user: %s whith"
				    " ip: %s", session_query->user_name,
				    session_query->ip);
			}
			else {
				SLIST_FOREACH(current, session_query->head,
				    next) {
					sock_send_msg_auth(sock_client,
					    current);
					log(LOG_INFO, "successful unauth user: "
					    "%s whith ip: %s",
					    current->user_name, current->ip);
				}
			}
			if (query->data.unauth.flag == by_user) {
				sock_send_reply(sock_client, REPLY_OK,
				    "successful unauth user: %s",
				    query->data.unauth.user_or_ip);
			}
			else if (query->data.unauth.flag == by_ip) {
				sock_send_reply(sock_client, REPLY_OK,
				    "successful unauth ip: %s",
				    query->data.unauth.user_or_ip);
			}
		}
		break;
	case OP_ISAUTH:
		if (!(session_query = isauth(
		    query->data.auth.ip, mode_direct, &err_msg))) {
			if (!err_msg) {
				sock_send_reply(sock_client, REPLY_OK,
				    "No session found with ip : %s",
				    query->data.auth.ip);
			}
			else {
				log(LOG_INFO, "function isauth error: %s",
				    err_msg);
				sock_send_reply(sock_client, REPLY_ERROR,
				    "isauth error with ip : %s : %s",
				    query->data.auth.ip, err_msg);
			}
		}
		else {
			bdd_session_update(session_query);
			sock_send_msg_auth(sock_client, session_query);
			sock_send_reply(sock_client, REPLY_OK,
			    "user %s is auth with ip %s since %d and "
			    "the session ends in %d sec",
			    session_query->user_name,
			    session_query->ip,
			    session_query->start_time,
			    session_query->expire_date);
		}
	break;
	case OP_LIST:
		if (!(session_query = list_user(mode_direct, &err_msg))) {
			log(LOG_INFO, "function list error: %s", err_msg);
			sock_send_reply(sock_client, REPLY_ERROR, "List error: "
			    "%s", err_msg);
		}
		else {
			if (!session_query->head) {
				sock_send_msg_auth(sock_client, session_query);
			}
			else {
				SLIST_FOREACH(current, session_query->head,
				    next) {
					sock_send_msg_auth(sock_client,
					    current);
				}
			}
			sock_send_reply(sock_client, REPLY_OK, "successful get "
			    "list");
		}
	break;
	case OP_HISTO:
		if (!(session_query = log_histo(query->data.log.start_time,
		    mode_direct, &err_msg))) {
			log(LOG_INFO, "function log error: %s", err_msg);
			sock_send_reply(sock_client, REPLY_ERROR, "Log error: "
			    "%s", err_msg);
		}
		else {
			if (!session_query->head) {
				sock_send_msg_log(sock_client, session_query);
			}
			else {
				SLIST_FOREACH(current, session_query->head,
				    next) {
					sock_send_msg_log(sock_client, current);
				}
			}
			sock_send_reply(sock_client, REPLY_OK, "successful get "
			    "histo");
		}
	break;
	default:
		log(LOG_WARNING, "false OP code");
	break;
	}
	if (session_query) {
		bdd_session_free(session_query);
	}
	if (err_msg) {
		free(err_msg);
	}
}
