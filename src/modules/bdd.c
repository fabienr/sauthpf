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
#define BDD_C

#include "compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sqlite3.h>

#include "bdd.h"
#include "conf.h"
#include "log.h"

session *bdd_get_session_by_user(char *user, char **err_msg) {

	if (!bdd_open(err_msg))
		return (NULL);

	if (!bdd_exec(true, err_msg, "SELECT * FROM sessions WHERE user = "
	    "\"%s\"", user))
		return (NULL);

	if (!current_session) {
		log(LOG_DEBUG, "No sessions found with user: %s", 
			    user);
		return (NULL);
	}
	return (current_session);
}

int bdd_insert(char *user, char *ip, char **err_msg)
{
	if (!bdd_open(err_msg))
		return (1);

	if (!bdd_exec(false, err_msg, "INSERT INTO sessions (user, ip, "
	    "expire_date, start_time) VALUES(\"%s\",\"%s\",%i,%i)", user, ip,
	    time(NULL) + conf_sessions_ttl, time(NULL)))
		return (1);
	return (0);
}

int bdd_insert_log(char *user, char *ip, time_t start_time, action_type type)
{
	if (!bdd_open(NULL))
		return (1);

	if (!bdd_exec(false, NULL, "INSERT INTO log (user, ip, start_time, "
	    "action_type, event_time) VALUES(\"%s\",\"%s\",%i,%i,%i)", user,
		ip, start_time, type, time(NULL)))
		return (1);
	return (0);
}

session *bdd_get_histo(time_t date, char **err_msg)
{
	if (!bdd_open(err_msg))
		return (NULL);
	if (!bdd_exec(true, err_msg, "SELECT * FROM log WHERE event_time > %u",
	    date))
		return (NULL);
	if (!current_session) {
		if (err_msg) {
			asprintf(err_msg, "No logs found from %u", (int)date);
		}
		log(LOG_DEBUG, "No logs found from %u", (int)date);
		return (NULL);
	}
	return (current_session);
}

session *bdd_get_list_user(char **err_msg)
{
	if (!bdd_open(err_msg))
		return (NULL);
	if (!bdd_exec(true, err_msg, "SELECT * FROM sessions WHERE expire_date "
	    "> %i", time(NULL)))
		return (NULL);
	if (!current_session) {
		if (err_msg) {
			asprintf(err_msg, "No sessions found with expire_date >"
			    " %d", (int)time(NULL));
		}
		log(LOG_DEBUG, "No sessions found with expire_date >"
			    " %d", (int)time(NULL));
		return (NULL);
	}
	return (current_session);
}

int bdd_delete(char *ip, char **err_msg)
{
	if (!bdd_open(err_msg))
		return (1);

	if (!bdd_exec(false, err_msg, "DELETE FROM sessions WHERE ip = \"%s\"",
	    ip))
		return (1);
	return 0;
}

session *bdd_get_session_by_ip(char *ip, char **err_msg)
{
	session *s;

	if (!bdd_open(err_msg))
		return (NULL);

	if (!bdd_exec(false, err_msg, "SELECT * FROM sessions WHERE ip = "
	    "\"%s\"", ip))
		return (NULL);

	if (!current_session) {
		log(LOG_DEBUG, "No session found with ip: %s", ip);
		return (NULL);
	}
	s = current_session;
	return (s);
}

session *bdd_session_get_expire(time_t current_time)
{
	if (!bdd_open(NULL))
		return (NULL);

	if (!bdd_exec(true, NULL, "SELECT * FROM sessions WHERE "
	    "expire_date <= \"%i\"", current_time))
		return (NULL);
	return (current_session);
}

bool bdd_session_delete_expire(time_t current_time)
{
	if (!bdd_open(NULL))
		return (false);

	if (!bdd_exec(true, NULL, "DELETE FROM sessions WHERE expire_date <= "
	    "\"%i\"", current_time))
		return (false);
	return (true);
}

void bdd_session_update(session *user)
{
	if (!user)
		return;
	user->expire_date = time(NULL) + conf_sessions_ttl;
	bdd_exec(false, NULL, "UPDATE sessions SET expire_date = \"%i\" WHERE "
	    "ip = \"%s\"", user->expire_date, user->ip);
	return;
}

void bdd_session_free(session *user)
{
	sessions *save_head;
	session *current_elem;
	if (!user)
		return ;
	if (user->head != NULL) {
		/* list of session */
		save_head = user->head;
		while (!SLIST_EMPTY(save_head)) {
			current_elem = SLIST_FIRST(save_head);
			SLIST_REMOVE_HEAD(save_head, next);
			free(current_elem->ip);
			free(current_elem->user_name);
			free(current_elem);
		}
		free(save_head);
	}
	else {
		free(user->ip);
		free(user->user_name);
		free(user);
	}
	return;
}

void bdd_quit(void)
{
	if(db != NULL)
		sqlite3_close(db);
}

void bdd_reload(void)
{
	/* XXX : reload bdd memory ... with new data ( if necessary ? ) */
}

static int callback(void *arg, int argc, char **argv,
    char **col_name)
{
	bool allow_multiple_session = *(bool*)arg;
	char *user_name, *ip;
	action_type type;
	time_t expire_date, start_time, event_time;
	
	session *this_session;

	/* vérifie si il y a déjà eu un appel à callback
	 * SI valeur de current_session != NULL ALORS
	 * afficher erreur et prendre le dernier
	 */
	if (!allow_multiple_session && current_session != NULL) {
		log(LOG_WARNING, "bdd_callback: more than one session found in"
		    "bdd, ignore it");
		return (1);
	}

	if (argc < 4) {
		log(LOG_WARNING, "bdd_callback: invalid table, not enough "
		    "column");
		return (1);
	}

	ip = strdup(argv[0]);
	user_name = strdup(argv[1]);

	if (argc == 5) {
		expire_date = 0;
		start_time = atoi(argv[2]);
		type = atoi(argv[3]);
		event_time = atoi(argv[4]);
	}
	else {
		expire_date = atoi(argv[2]);
		start_time = atoi(argv[3]);
		type = 0;
		event_time = 0;
	}
	
	this_session = bdd_session_new(ip, user_name, type, event_time,
	    expire_date, start_time, current_session);

	if ( current_session == NULL)
		current_session = this_session;
	
	free(ip);
	free(user_name);
	return (0);
}

static bool bdd_open(char **err_msg)
{
	int rc;
	if (db == NULL) {
		if (!file_exists(conf_bdd_path)) {
			log(LOG_WARNING, "the database file '%s' doesn't exist",
			    conf_bdd_path);
			if(err_msg)
				asprintf(err_msg, "the database file '%s' "
				    "doesn't exist",conf_bdd_path);
			return (false);
		}
		rc = sqlite3_open(conf_bdd_path, &db);
		if (rc) {
			log(LOG_WARNING, "can't open database: %s",
			    sqlite3_errmsg(db));
			if(err_msg)
				asprintf(err_msg, "can't open database: %s",
				    sqlite3_errmsg(db));
			sqlite3_close(db);
			db = NULL;
			return (false);
		}
	}
	return (true);
}

static bool bdd_exec(bool allow_multiple_session, char **err_msg, 
    const char *sql_fmt,...)
{
	int rc;
	char *errmsg = 0;
	char *sql;
	va_list ap;

	current_session = NULL;

	va_start(ap, sql_fmt);
	if (vasprintf(&sql, sql_fmt, ap) < 0) {
		log(LOG_WARNING, "vasprintf error : %m");
		va_end(ap);
		return (false);
	}
	va_end(ap);

	log(LOG_DEBUG, "exec sql: %s", sql);
	rc = sqlite3_exec(db, sql, callback, (void*)&allow_multiple_session,
	    &errmsg);
	if (rc != SQLITE_OK) {
		log(LOG_INFO, "SQL error: %s", errmsg);
		if(err_msg) {
			asprintf(err_msg, "SQL error: %s", errmsg);
		}
		sqlite3_free(errmsg);
		free(sql);
		return (false);
	}
	free(sql);
	return (true);
}

session *bdd_session_new(const char *ip, const char *user_name,
    action_type type, time_t event_time, time_t expire_date, 
    time_t start_time, session *first_session)
{
	/* malloc et préparation des champs */
	session *user;

	/*if (expire_date != 0 && expire_date <= time(NULL)) {
		log(LOG_DEBUG, "expire_date: %i <= time: %i", expire_date,
		    time(NULL));
		return (NULL);
	}*/

	user = calloc(1, sizeof(session));
	user->ip = strdup(ip);
	user->user_name = strdup(user_name);
	user->expire_date = expire_date;
	user->start_time = start_time;
	user->type = type;
	user->event_time = event_time;

	if (first_session != NULL) {
		if (first_session->head == NULL) {
			first_session->head = malloc(
			    sizeof(*first_session->head));
			SLIST_INIT(first_session->head);
			SLIST_INSERT_HEAD(first_session->head, first_session,
			    next);
		}
		SLIST_INSERT_HEAD(first_session->head, user, next);
		user->head = first_session->head;
	}

	return (user);
}

static bool file_exists(char *file)
{
	struct stat fst;
	if (stat(file, &fst) == -1)
		return (false); /* file doesnt exist! */
	return (true);
}
