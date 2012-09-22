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
#define CONF_C

#include "compat.h"

#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "conf.h"
#include "log.h"

int load_config(const char *file)
{
	char *file_content = NULL;
	int i, ret = 0, nline = 1;

	file_content = file_get_contents(file);
	if (file_content == NULL) {
		log(LOG_WARNING, "cannot load content of config file %s", file);
		ret = 1;
		goto end;
	}

	for (i=0; file_content[i]; i++) {
		if (ret == 1) {
			nline++;
			ret = 0;
		}

		/* end of line, increment count */
		if (file_content[i] == '\n') {
			nline++;
			continue;
		}

		/* skip space at beginning  */
		while (file_content[i] && isspace(file_content[i])) {
			if (file_content[i] == '\n') {
				nline++;
				i++;
				continue;
			}
			i++;
		}

		/* it's a comment ? */
		if (file_content[i] == '#') {
			while (file_content[i] && file_content[i] != '\n')
				i++;
			if (file_content[i] == '\n') {
				nline++;
				continue;
			}
			if (!file_content[i])
				break;
		}
		/* test syntax : <var> = <arg> */
		else if (file_content[i]) {
			char *var, *arg;

			arg = &(file_content[i]);

			while (file_content[i] && file_content[i] != '=' &&
			    file_content[i] != '#' && file_content[i] != '\n')
				i++;

			if (file_content[i] != '=' ) {
				log(LOG_WARNING, "syntax error in configuration"
				    " file %s:l%d, should be <arg> = <var>",
				    file, nline);
				i--;
				continue;
			}
			file_content[i] = '\0';

			var = &(file_content[++i]);

			while (file_content[i] && file_content[i] != '\n' &&
			    file_content[i] != '#')
				i++;

			if (file_content[i] == '\n') {
				file_content[i] = '\0';
				ret = 1;
			}
			else if (file_content[i] == '#') {
				file_content[i++] = '\0';
				while (file_content[i] &&
				    file_content[i] != '\n')
					i++;
				ret = 1;
			}
			else {
				i--;
			}

			trim(arg, TRIM_BOTH);
			trim(var, TRIM_BOTH);

			if (!*var || !*arg) {
				log(LOG_WARNING, "syntax error in configuration"
				    " file %s:l%d, should be <arg> = <var>",
				    file, nline);
				continue;
			}
			log(LOG_INFO, "parse arg %s", arg);
			if (!strcmp(arg, "bdd_path")) {
				if (conf_bdd_path != NULL) {
					log(LOG_WARNING, "conf_bdd_path : "
					    "already define %s:l%d",
					    file, nline);
					free(conf_bdd_path);
				}
				conf_bdd_path = strdup(var);
			} else if (!strcmp(arg, "socket_path")) {
				if (conf_socket_path != NULL) {
					log(LOG_WARNING, "conf_socket_path : "
					    "already define %s:l%d",
					    file, nline);
					free(conf_socket_path);
				}
				conf_socket_path = strdup(var);
			} else if (!strcmp(arg, "pid_path")) {
				if (conf_pid_path != NULL) {
					log(LOG_WARNING, "conf_pid_path : "
					    "already define %s:l%d",
					    file, nline);
					free(conf_pid_path);
				}
				conf_pid_path = strdup(var);
			} else if (!strcmp(arg, "user")) {
				if (conf_user != NULL) {
					log(LOG_WARNING, "conf_user : "
					    "already define %s:l%d",
					    file, nline);
					free(conf_user);
				}
				conf_user = strdup(var);
			} else if (!strcmp(arg, "group")) {
				if (conf_group != NULL) {
					log(LOG_WARNING, "conf_group : "
					    "already define %s:l%d",
					    file, nline);
					free(conf_group);
				}
				conf_group = strdup(var);
			} else if (!strcmp(arg, "url_rewrite_program")) {
				if (conf_url_rewrite_program != NULL) {
					log(LOG_WARNING,
					    "conf_url_rewrite_program : "
					    "already define %s:l%d",
					    file, nline);
					free(conf_url_rewrite_program);
				}
				conf_url_rewrite_program = strdup(var);
			} else if (!strcmp(arg, "sessions_ttl")) {
				if (conf_sessions_ttl) {
					log(LOG_WARNING, "session_ttl : "
					    "already define %s:l%d",
					    file, nline);
				}
				if (string_is_int(var))
					conf_sessions_ttl = atoi(var);
				else
					log(LOG_WARNING, "session_ttl : "
					    "var is not an int %s:l%d",
					    file, nline);
			} else if (!strcmp(arg, "secure_auth")) {
				if (conf_secure_auth != undef) {
					log(LOG_WARNING, "secur_auth : "
					    "already define %s:l%d",
					    file, nline);
				}
				if (!strcasecmp(var, "true"))
					conf_secure_auth = true;
				else if (!strcasecmp(var, "false"))
					conf_secure_auth = false;
				else
					log(LOG_WARNING, "secur_auth : "
					    "var != true or false %s:l%d",
					    file, nline);
			}
			else {
				log(LOG_WARNING, "error in configuration"
				    " file %s:%d : unknow arg '%s'",
				    file, nline, arg);
			}
		}
	}
	ret = 0;
	nline++;

end:
	if (file_content)
		free(file_content);

	if (conf_bdd_path == NULL)
		conf_bdd_path = strdup(CONF_DEFAULT_BDD_PATH);

	if (conf_socket_path == NULL)
		conf_socket_path = strdup(CONF_DEFAULT_SOCKET_PATH);

	if (conf_pid_path == NULL)
		conf_pid_path = strdup(CONF_DEFAULT_PID_PATH);

	if (conf_user == NULL)
		conf_user = strdup(CONF_DEFAULT_USER);

	if (conf_group == NULL)
		conf_group = strdup(CONF_DEFAULT_GROUP);

	if (conf_sessions_ttl == 0)
		conf_sessions_ttl = CONF_DEFAULT_SESSIONS_TTL;

	if (conf_secure_auth == undef)
		conf_secure_auth = CONF_DEFAULT_SECURE_AUTH;

	return (ret);
}

void free_config(void)
{
	if (conf_bdd_path != NULL) {
		free(conf_bdd_path);
		conf_bdd_path = NULL;
	}
	if (conf_socket_path != NULL) {
		free(conf_socket_path);
		conf_socket_path = NULL;
	}
	if (conf_pid_path != NULL) {
		free(conf_pid_path);
		conf_pid_path = NULL;
	}
	if (conf_user != NULL) {
		free(conf_user);
		conf_user = NULL;
	}
	if (conf_group != NULL) {
		free(conf_group);
		conf_group = NULL;
	}
	if (conf_url_rewrite_program != NULL) {
		free(conf_url_rewrite_program);
		conf_url_rewrite_program = NULL;
	}
}

static int string_is_int(const char *string)
{
	if (!string || !*string)
		return (0);
	if (*string != '-' && *string != '+' && (*string < '0'||*string > '9'))
		return (0);
	for (string++; *string; string++)
		if (*string < '0' || *string > '9')
			return (0);
	return (1);
}


static int trim(char *string, int type)
{
	int len = 0;
	char *start, *end = NULL, *str;
	if (!string)
		return (0);
	if (type == TRIM_LEFT || type == TRIM_BOTH)
		for (start = string; *start && isspace(*start); start++);
	else
		start = string;
	if (type == TRIM_RIGHT || type == TRIM_BOTH) {
		for (str = start; *str; str++)
			if (!isspace(*str))
				end = str;
		if(end)
			end++;
	}
	if (start == string) {
		if (end && *end) {
			*end = '\0';
			len = end - string;
		}
		else if (end)
			len = end - string;
		else
			len = strlen(string);
	} else {
		for (str = start;*str && (!end || str != end);str++, string++,
		    len++)
			*string = *str;
		*string = '\0';
	}
	return (len);
}

int change_rights ()
{
	if (getuid () == 0 ) {
		struct passwd *pw;
		struct group *gr;
		gid_t gid;
		if ((gr = getgrnam(conf_group))) {
			gid = gr->gr_gid;
			if (setresgid(gid, gid, gid) != 0) {
				log(LOG_WARNING, "cannot change gid");
				return (1);
			}
			if (initgroups(conf_user, gid) == -1) {
				log(LOG_WARNING, "cannot change gid");
				return (1);
			}
		}
		else {
			log(LOG_WARNING, "cannot find group %s on system", 
			    conf_group);
			return (1);
		}
		if ((pw = getpwnam(conf_user))) {
			if (chown(conf_socket_path, pw->pw_uid, gid) == -1) {
				log(LOG_WARNING, "cannot change owner of "
				    "%s : %m", conf_socket_path);
				return (1);
			}
			if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) != 0){
				log(LOG_WARNING, "cannot change uid");
				return (1);
			}
		}
		else {
			log(LOG_WARNING, "cannot find user %s on system", 
			    conf_user);
			return (1);
		}
		return (0);
	}
	log(LOG_WARNING, "User isn't root");
	return (1);
}

char *file_get_contents(const char *filename)
{
	int f;
	char *content;
	int nread, file_size;
	struct stat s;
	if ((f = open(filename, O_RDONLY)) < 0) {
		log(LOG_INFO, "open error on %s : %m", filename);
		return (NULL);
	}
	if (fstat(f, &s)) {
		log(LOG_INFO, "fstat error on %s : %m", filename);
		close(f);
		return (NULL);
	}
	file_size = (int)s.st_size;
	content = (char *)malloc(file_size + 1);
	if ((nread = read(f, content, file_size)) == -1) {
		free(content);
		log(LOG_INFO, "read error on %s : %m", filename);
		return (NULL);
	}
	content[nread] = '\0';
	if (nread != file_size) {
		log(LOG_INFO, "read only %d of %d byte from '%s'", nread,
		    file_size, filename);
	}
	close(f);
	return (content);
}
