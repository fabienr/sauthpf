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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>

#include "../modules/conf.h"
#include "../modules/bool.h"
#include "../modules/log.h"
#include "../modules/users.h"

#define BUFF_MAX_SIZE 128

#ifndef DEFAULT_CONF_FILE
#define DEFAULT_CONF_FILE "/etc/sauthpf.conf"
#endif

#define FLAG_AUTH	1
#define FLAG_UNAUTH	2
#define FLAG_ISAUTH	3
#define FLAG_LIST	4
#define FLAG_HISTO	5
#define FLAG_PING	6

#define VERSION		"0.1"
#define SUBSYS		"sauthpf-client"

void usage(void)
{
	printf(
		"exemple : \n"
		"\t-V : display version\n"
		"\t-v : Mode Verbose ON, display LOG_INFO\n" 
		"\t-vv : Mode Verbose ON, display LOG_DEBUG\n" 
		"\t-d : enable mode debug, write on stderr\n"
		"\t-f <file> : use this configuration file\n"
		"\t-A : auth this -n <user> whith -i <ip> and -p <password> if "
		    "secure auth is allow\n"
		"\t-U : unauth all sessions of this -n <user> or unauth this -i"
		    " <ip>\n"
		"\t-T: isauth this -i <ip>\n"
		"\t-L: list connected users\n"
		"\t-P : Send ping to the daemon\n"
		"\t-n : <user> : user's name\n"
		"\t-i : <ip> : ip address\n"
		"\t-p : <password> : user's password\n"
		"\t-h: <date> : historique de connection from date\n"
	);
	free_config();
	exit(0);
}

int main(int argc, char **argv)
{
	char *file = NULL, ch;
	int flag = 0;
	char *user = NULL, *ip = NULL, *password = NULL;
	time_t date;
	session *list, *current, *histo, *session_auth, *session_unauth,
	    *session_isauth;
	char *err_msg = NULL;
	int verbose = 0;
	int ping = 0;
	bool debug = false;

	while ((ch = getopt(argc, argv, "Vvdf:AUTLPn:i:p:h:")) != EOF)
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
		case 'A':
			if (flag)
				usage();
			flag = FLAG_AUTH;
			break;
		case 'U':
			if (flag)
				usage();
			flag = FLAG_UNAUTH;
			break;
		case 'T':
			if (flag)
				usage();
			flag = FLAG_ISAUTH;
			break;
		case 'L':
			if (flag)
				usage();
			flag = FLAG_LIST;
			break;
		case 'P':
			if (flag)
				usage();
			flag = FLAG_PING;
			break;
		case 'n':
			user = optarg;
			break;
		case 'i':
			ip = optarg;
			break;
		case 'p':
			password = optarg;
			break;
		case 'h':
			if (flag)
				usage();
			flag = FLAG_HISTO;
			date = atoi(optarg);
			break;
		default:
			usage();
		}
	if (file == NULL)
		file = DEFAULT_CONF_FILE;

	log_init(SUBSYS, verbose, debug);
	log(LOG_DEBUG, "start using configuration file '%s'", file);

	if (load_config(file) != 0) {
		log(LOG_WARNING, "load_config error");
		goto error;
	}

	switch (flag) {
	case 0:
		usage();
	case FLAG_AUTH:
		if (conf_secure_auth == false && (!user || !ip))
			usage();
		else if (conf_secure_auth == true && (!user || !ip ||
		    !password)) {
			printf("WARNING : Password is required because "
			    "secure_auth is enable\n");
			usage();
		}
		if ((session_auth = auth(user, ip, password, mode_auto,
		    &err_msg))) {
			printf("successful auth user: %s with ip : %s\n",
			    session_auth->user_name,
			    session_auth->ip);
			bdd_session_free(session_auth);
		}
		else {
			printf("ERROR: %s\n", err_msg);
		}
		goto end;
	case FLAG_UNAUTH:
		if (!user && !ip)
			usage();
		if (user)
		{
			if ((session_unauth = unauth(by_user, user, mode_auto,
			    &err_msg))) {
				if (!session_unauth->head) {
				printf("successful unauth user: %s with ip : "
				    "%s\n", session_unauth->user_name,
				    session_unauth->ip);
				bdd_session_free(session_unauth);
				}
				else {
					SLIST_FOREACH(current,
					    session_unauth->head, next) {
						printf("successful unauth user:"
						    " %s with ip : %s\n",
						    current->user_name,
						    current->ip);
					}
				bdd_session_free(session_unauth);
				}
			}
			else {
				printf("ERROR: %s\n", err_msg);
			}
		}
		else {
			if ((session_unauth = unauth(by_ip, ip, mode_auto,
			    &err_msg))) {
				printf("successful unauth user: %s with ip :"
				    " %s\n", session_unauth->user_name,
				    session_unauth->ip);
				bdd_session_free(session_unauth);
			}
			else {
				printf("ERROR: %s\n", err_msg);
			}
		}
		goto end;
	case FLAG_ISAUTH:
		if (!ip)
			usage();
		if ((session_isauth = isauth(ip, mode_auto, &err_msg))) {
			printf("user %s is auth with ip %s since %d and the "
			    "session ends in %d sec",
			    session_isauth->user_name, session_isauth->ip,
			    (int)session_isauth->start_time,
			    (int)(session_isauth->expire_date - time(NULL)));
			bdd_session_free(session_isauth);
		}
		else if (err_msg) {
			printf("ERROR: %s\n", err_msg);
		}
		else {
			printf("INFO : no session found with ip : %s\n", ip);
		}
		goto end;
	case FLAG_LIST:
		if ((list = list_user(mode_auto, &err_msg))) {
			if (!list->head) {
				printf("user %s is log on with ip %s "
				    "since %d\n", list->user_name, list->ip,
				    (int)list->start_time);
				bdd_session_free(list);
			}
			else {
				SLIST_FOREACH(current, list->head, next) {
					printf("user %s is log on with ip %s "
					    "since %d\n", current->user_name,
					    current->ip,
					    (int)current->start_time);
				}
				bdd_session_free(list);
			}
		}
		else {
			printf("ERROR: %s\n", err_msg);
		}
		goto end;
	case FLAG_HISTO:
		if (!date)
			usage();
		if ((histo = log_histo(date, mode_auto, &err_msg))) {
			if (!histo->head) {
				if (histo->type == 0){
					printf("user %s is log on at %d"
					    " with ip %s since %d\n",
					    histo->user_name,
					    (int)histo->event_time,
					    histo->ip,
					    (int)histo->start_time);
				}
				else {
					printf("user %s is log off at "
					    "%d with ip %s and he was log on "
					    "since %d\n", histo->user_name,
					    (int)histo->event_time, histo->ip,
					    (int)histo->start_time);
				}
				bdd_session_free(histo);
			}
			else {
				SLIST_FOREACH(current, histo->head, next) {
					if (current->type == 0){
						printf("user %s is log "
						    "on at %d with ip %s\n",
						    current->user_name,
						    (int)current->event_time,
						    current->ip);
					}
					else {
						printf("user %s is log "
						    "off at %d with ip %s and "
						    "he was log on since %d\n",
						    current->user_name,
						    (int)current->event_time,
						    current->ip,
						    (int)current->start_time);
					}
				}
				bdd_session_free(histo);
			}
		}
		else {
			printf("ERROR: %s\n", err_msg);
		}
		goto end;
	case FLAG_PING:
		ping = send_ping(&err_msg);
		if (ping == 1)
			printf("PONG\n");
		else 
			printf("Ping error: %s\n", err_msg);
		break;
	default:
		printf("ERROR: Invalid Flag");
	}

end:
	if (err_msg)
		free(err_msg);
	/* Free config memory */
	free_config();
	bdd_quit();
	/* Close log file */
	log(LOG_DEBUG, "nice quit");
	log_quit();
	exit(0);
error:
	if (err_msg)
		free(err_msg);
	/* Free config memory */
	free_config();
	bdd_quit();
	/* Close log file */
	log_quit();
	exit(1);
}

