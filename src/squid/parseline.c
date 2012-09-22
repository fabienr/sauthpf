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
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "parseline.h"
#include "../modules/log.h"

line *line_new(void)
{
	return (calloc(1, sizeof(line)));
}

void line_free(line *parseline)
{
	/* libérer la mémoire en faisant attention au pointeur NULL */
	if (!parseline)
		return ;

	free(parseline->url);
	free(parseline->src_ip);
	free(parseline->src_domain);
	free(parseline->user);
	free(parseline->method);
	free(parseline->url_group);
	free(parseline->opt);
	free(parseline);
}

line *line_from_string(char * line_args)
{
	char *field, *u_field;
	line *parseline;
	int i = 0;

	parseline = line_new();

	field = strtok(line_args," \t\n");
	while (field != NULL) {
		switch (i) {
		case 0: /* url */
			parseline->url = strdup(field);
		break;
		case 1: /* src  et domain*/
			u_field = strchr(field,'/');
			if (u_field != NULL) {
				*u_field = '\0';
				parseline->src_ip = strdup(field);
				*u_field++ = '/';
				/* ++ pris en compte après */
				if( *u_field != '-') {
					parseline->src_domain =
					    strdup(u_field);
				}
			}
			else {
				parseline->src_ip = strdup(field);
			}
			break;
		case 2: /* user */
			if(strcmp(field, "-")) {
				parseline->user = strdup(field);
				for (field=parseline->user; *field != '\0';
				    field++)
					*field = tolower(*field);
			}
			break;
		case 3: /* method */
			parseline->method = strdup(field);
			break;
		case 4:
			/* group */
			parseline->url_group = strdup(field);
			break;
		default:
			if (!parseline->opt)
				parseline->opt = field;
			else
				*(field - 1) = ' ';
			break;
		}
		i++;
		field = strtok(NULL, " \t\n");
	}

	if (parseline->opt)
		parseline->opt = strdup(parseline->opt);

	if (i < 5) {
		log(LOG_INFO, "parseline error : "
		    "not enough element in the line");
		line_free(parseline);
		return (NULL);
	}

	return (parseline);
}

char *line_to_string(line *parseline)
{
	char *str;
	asprintf(&str, "%s %s/%s %s %s %s %s\n", parseline->url,
	    parseline->src_ip, parseline->src_domain?parseline->src_domain:"-",
  	    parseline->user ? parseline->user : "-", parseline->method,
	    parseline->url_group, parseline->opt);
	return (str);
}
