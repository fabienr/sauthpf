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

#include "../modules/conf.h"
#include "../modules/bdd.h"
#include "../modules/bool.h"
#include "../modules/fwl.h"
#include "../modules/log.h"

#ifndef DEFAULT_CONF_FILE
#define DEFAULT_CONF_FILE "/etc/sauthpf.conf"
#endif

#define VERSION		"0.1"
#define SUBSYS		"sauthpf-cleaner"

void usage(void)
{
	printf
	(	"exemple : \n"
		"\t-V : display version\n"
		"\t-v : Mode Verbose ON, display LOG_INFO\n" 
		"\t-vv : Mode Verbose ON, display LOG_DEBUG\n" 
		"\t-d : enable mode debug, write on stderr\n"
		"\t-f <file> : use this configuration file\n"
	);
}

int main(int argc, char **argv)
{
	char *file = NULL, ch;
	session *user, *current;
	struct timeval start;
	int verbose = 0;
	bool debug = false;
	
	while ((ch = getopt(argc, argv, "vdVf:")) != EOF)
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
	log(LOG_DEBUG, "start using configuration file '%s'", file);

	if (load_config(file) != 0) {
		log(LOG_WARNING, "load_config error");
		goto error;
	}

	if (fwl_init() != 0) {
		log(LOG_WARNING, "fwl_init error");
		goto error;
	}

	if (change_rights() != 0) {
		log(LOG_WARNING, "change_rights error");
		goto error;
	}

	time_t now = time(NULL);
	user = bdd_session_get_expire(now);
	if (user && !user->head) {
		start.tv_sec = user->start_time;
		start.tv_usec = 0;
		fwl_unauth(user->user_name, user->ip, start);
		bdd_session_free(user);
	}
	else if (user) {
		SLIST_FOREACH(current, user->head, next) {
			start.tv_sec = current->start_time;
			start.tv_usec = 0;
			fwl_unauth(current->user_name, current->ip, start);
		}
		bdd_session_free(user);
	}
	bdd_session_delete_expire(now);

	/* Close /dev/fwl */
	fwl_quit();
	/* Close database */
	bdd_quit();
	/* Free config memory */
	free_config();
	/* Close log */
	log_quit();
	return (0);
error:
	/* Close /dev/pf */
	fwl_quit();
	/* Close database */
	bdd_quit();
	/* Free config memory */
	free_config();
	/* Close log file */
	log_quit();
	return (1);
}
