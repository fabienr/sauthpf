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
#include "bool.h"
#ifndef CONF_H
#define CONF_H

#ifdef CONF_C
char *conf_bdd_path = NULL;
char *conf_socket_path = NULL;
char *conf_pid_path = NULL;
char *conf_user = NULL;
char *conf_group = NULL;
char *conf_url_rewrite_program = NULL;
int conf_sessions_ttl = 0;
bool conf_secure_auth = undef;


#define TRIM_LEFT	1
#define TRIM_RIGHT	2
#define TRIM_BOTH	0

#ifndef CONF_DEFAULT_BDD_PATH
#define CONF_DEFAULT_BDD_PATH		"/var/db/sauthpf/sessions.sqlite"
#endif
#ifndef CONF_DEFAULT_SOCKET_PATH
#define CONF_DEFAULT_SOCKET_PATH	"/var/run/sauthpf.sock"
#endif
#ifndef CONF_DEFAULT_PID_PATH
#define CONF_DEFAULT_PID_PATH		"/var/run/sauthpf.pid"
#endif
#ifndef CONF_DEFAULT_USER
#define CONF_DEFAULT_USER		"_sauthpf"
#endif
#ifndef CONF_DEFAULT_GROUP
#define CONF_DEFAULT_GROUP		"_sauthpf"
#endif
#ifndef CONF_DEFAULT_SESSIONS_TTL
#define CONF_DEFAULT_SESSIONS_TTL	3600
#endif
#ifndef CONF_DEFAULT_SECURE_AUTH
#define CONF_DEFAULT_SECURE_AUTH	true
#endif

static int string_is_int(const char *);
static int trim(char *, int);

#else

extern char *conf_bdd_path;
extern char *conf_socket_path;
extern char *conf_pid_path;
extern char *conf_user;
extern char *conf_group;
extern char *conf_url_rewrite_program;
extern int conf_sessions_ttl;
extern bool conf_secure_auth;

#endif

int load_config(const char *);
void free_config(void);
char *file_get_contents(const char *);
int change_rights ();


#endif
