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
#ifndef SOCK_H
#define SOCK_H

#include "users.h"

#define SAUTHPF_PROTO_VERSION 1

#define PROTO_DATA_SIZE		128
#define PROTO_ANSWER_MSG_SIZE	PROTO_DATA_SIZE-sizeof(msg_reply)
#define PROTO_AUTH_STR_SIZE	PROTO_DATA_SIZE/2
#define MAX_REPLY_CODE		10
#define MAX_OP_CODE		9

typedef enum {
	REPLY_OK,
	REPLY_ERROR
} msg_reply;

typedef enum {
	OP_AUTH,
	OP_UNAUTH,
	OP_ISAUTH,
	OP_LIST,
	OP_HISTO,
	OP_PING,
	OP_PONG,
	OP_ANSWER,
	OP_MSG_AUTH,
	OP_MSG_LOG
} msg_operation;

typedef struct _msg_auth {
	char user[PROTO_AUTH_STR_SIZE];
	char ip[PROTO_AUTH_STR_SIZE];
	char password[PROTO_AUTH_STR_SIZE];
	time_t start_time;
	time_t expire_date;
} msg_auth;

typedef struct _msg_unauth {
	char user_or_ip[PROTO_AUTH_STR_SIZE];
	flag_unauth flag;
} msg_unauth;

typedef struct _msg_log {
	char user[PROTO_AUTH_STR_SIZE];
	char ip[PROTO_AUTH_STR_SIZE];
	time_t start_time;
	time_t event_time;
	action_type type;
} msg_log;

typedef struct _msg_answer {
	msg_reply answer_code;
	char answer_msg[PROTO_ANSWER_MSG_SIZE];
} msg_answer;

typedef struct _message {
	int version;
	msg_operation op;
	union { msg_auth auth; msg_unauth unauth; msg_answer answer; 
	    msg_log log;} data;
} msg;

int socket_server(char *);
int socket_client(char *, char **);
void close_socket_server(void);

int sock_read_msg(int , msg *, char **);
int sock_send_msg(int , msg *, char **);
int sock_send_auth(int , msg *, char *, char *, char *, char **);
int sock_send_unauth(int , msg *, flag_unauth, char *, char **);
int sock_send_isauth(int , msg *, char *,char **);
int sock_send_list_user(int , msg *, char **);
int sock_send_log_histo(int , msg * , time_t, char **);
int sock_send_ping(int , msg *, char **);
int sock_send_reply(int , int , char *, ...);
int sock_send_msg_auth(int, session *);
int sock_send_msg_log(int , session *);
int sock_read_query(int , msg *);

#ifdef SOCK_C
static int sock_server;
bool in_action = false;
bool end_process = false;
#else
extern bool in_action;
extern bool end_process;
#endif

#endif
