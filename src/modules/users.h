/*
 * Copyright (c) 2009 Denis Dechaux-Blanc <ded@asystant.net>
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
#ifndef USERS_H
#define USERS_H
#include "bdd.h"

typedef enum {
  mode_auto = 0, mode_direct = 1, mode_socket = 2
} auth_unauth_mode;

typedef enum {
  by_user,
  by_ip
} flag_unauth;

#include "sock.h"

session *auth(char *, char *, char *, auth_unauth_mode, char **);
session *unauth(flag_unauth, char *, auth_unauth_mode, char **);
session *isauth(char *, auth_unauth_mode, char **);
session *list_user(auth_unauth_mode, char **);
session *log_histo(time_t, auth_unauth_mode, char **);
int send_ping(char **);

#ifdef USERS_C
/*static inline int check_pid (char **);*/
static inline int check_sock (int *, auth_unauth_mode *, char **);
static inline session *read_answer_switch(int, msg *, action_type , char **);
#endif

#endif
