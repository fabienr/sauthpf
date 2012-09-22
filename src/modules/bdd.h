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
#ifndef BDD_H
#define BDD_H

#include <time.h>
#include "openbsd_queue.h"
#include "bool.h"

typedef SLIST_HEAD(, _session) sessions;

typedef enum {
	AUTH,
	UNAUTH,
	ISAUTH,
	LIST,
	HISTO
} action_type;

typedef struct _session {
	char *ip;
	time_t expire_date;
	time_t start_time;
	time_t event_time;
	char *user_name;
	SLIST_ENTRY(_session) next;
	sessions *head;
	action_type type;
} session;

session *bdd_get_session_by_user(char *, char **);
session *bdd_get_session_by_ip(char *, char **);
session *bdd_get_histo(time_t, char **);
session *bdd_get_list_user(char **);
int bdd_insert(char *, char *, char **);
int bdd_insert_log(char *, char *,time_t, action_type);
int bdd_delete(char *, char **);
void bdd_session_update(session *);
void bdd_session_free(session *);
session *bdd_session_get_expire(time_t);
bool bdd_session_delete_expire(time_t);
session *bdd_session_new(const char *, const char *, action_type, 
    time_t, time_t, time_t, session *);
void bdd_quit(void);
void bdd_reload(void);

#ifdef BDD_C

#include <sqlite3.h>
sqlite3 *db = NULL;

session *current_session = NULL;

static bool bdd_open(char **);
static bool bdd_exec(bool, char **, const char *, ...);
static int callback(void*, int, char**, char**);
static bool file_exists(char *);

#endif

#endif
