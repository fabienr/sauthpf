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
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "../modules/conf.h"
#include "../modules/bdd.h"
#include "../modules/bool.h"
#include "../modules/log.h"
#include "../modules/users.h"
#include "parseline.h"
#include "rewrite_program.h"

#ifndef DEFAULT_CONF_FILE
#define DEFAULT_CONF_FILE	"/etc/sauthpf.conf"
#endif

#define VERSION		"0.1"
#define MAX_BUF		4096
#define SUBSYS		"sauthpf-squid"

bool sauthpf_squid_run = true;

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
	char *file = NULL, ch, in[MAX_BUF], *str = NULL;
	line *parseline;
	session *user;
	int verbose = 0;
	bool debug = false;

	while ((ch = getopt(argc, argv, "Vvdf:")) != EOF)
		switch (ch) {
		case 'V':
			fprintf(stderr, "%s : %s\n", SUBSYS, VERSION);
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

	if(load_config(file) != 0) {
		free_config();
		log_quit();
		exit(1);
	}

	/* lire sur stdin tant que le programme n'est pas tuer */
	while (sauthpf_squid_run) {
		/* lire la ligne */
		if (!fgets(in, MAX_BUF, stdin)) {
			if (!feof(stdin))
				log(LOG_WARNING, "fgets error : %m");
			/* XXX : fin de l'éxécution du programme ? */
			break;
		}

		log(LOG_DEBUG, "string: '%s'", in);

		/* parse la ligne */
		if (!(parseline = line_from_string(in))) {
			log(LOG_INFO, "invalid format line");
			puts("");
			fflush(stdout);
			continue;
		}

		log(LOG_DEBUG, "parseline: %s %s/%s %s %s %s %s\n",
		    parseline->url,
		    parseline->src_ip,
		    parseline->src_domain ? parseline->src_domain : "-",
		    parseline->user ? parseline->user : "-",
		    parseline->method,
		    parseline->url_group,
		    parseline->opt);

		if ((user = isauth(parseline->src_ip, mode_auto, NULL))
		    != NULL) {
			if (parseline->user)
				free(parseline->user);
			parseline->user = strdup(user->user_name);
			bdd_session_free(user);
		}

		/* converti line en string */
		str = line_to_string(parseline);
		line_free(parseline);

		/* appel le programme redirecteur : str -> redirecteur */
		if (!rewrite_program_write(str)) {
			log(LOG_WARNING, "rewrite_program_write fatal error");
			free(str);
			puts("");
			fflush(stdout);
			continue;
		}

		/* libère la mémoire de str qui ne sert plus à rien */
		free(str);

		/* appel le programme redirecteur : redirecteur -> str */
		if (!(str = rewrite_program_read())) {
			log(LOG_WARNING, "rewrite_program_read fatal error");
			puts("");
			fflush(stdout);
			continue;
		}

		fprintf(stdout, "%s", str);
		fflush(stdout);

		/* libère la mémoire de str qui ne sert plus à rien */
		free(str);
	}

	/* termine le programme rewrite_url */
	program_engine_quit();
	/* ferme la base de données */
	bdd_quit();
	/* libérer la mémoire de la config */
	free_config();

	/* ferme le log */
	log_quit();

	return (0);
}
