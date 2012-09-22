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
#define USERS_C

#include "compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>

#include <sys/time.h>

#include "users.h"
#include "bdd.h"
#include "conf.h"
#include "bool.h"
#include "fwl.h"
#include "log.h"
#include "sock.h"

#define BUFF_MAX_SIZE 128
#define display_type(var) ((var==0)?"AUTH":(var==1)?"UNAUTH":(var==2)?"ISAUTH":\
    (var==3)?"LIST":(var==4)?"HISTO":"Invalid type")

/*
static inline int check_pid (char **err_msg) {
	pid_t exist_pid;
	char *pid_file = NULL;

	return (0);

	pid_file = file_get_contents(conf_pid_path);
	if (pid_file == NULL) {
		log(LOG_WARNING, "invalid conf_pid_path or file: %m");
		if (err_msg)
			asprintf(err_msg, "invalid conf_pid_path or file:"
			    "%s", strerror(errno));
		return(1);
	}
	else if (kill((exist_pid = atoi(pid_file)), 0) < 0) {
		log(LOG_WARNING, "daemon down : %m");
		if (err_msg)
			asprintf(err_msg, "daemon down: %s",
			    strerror(errno));
		free(pid_file);
		return(1);
	}
	free(pid_file);
	return(0);
}
*/

static inline int check_sock (int *sock, auth_unauth_mode *mode, 
    char **err_msg) {
	
		if ((*sock = socket_client(conf_socket_path, err_msg))
		    == -1) {
			log(LOG_WARNING, "Invalid socket");
			return (0);
		}
		else {
			return (1);
		}
}

static inline session *read_answer_switch (int socket, msg *query,
    action_type type, char **err_msg) {
	session *all_session = NULL, *current = NULL;
	do {
		if (sock_read_msg(socket, query, err_msg)) {
			log(LOG_WARNING, "read message error %s", *err_msg);
			close(socket);
			if (all_session)
				bdd_session_free(all_session);
			return (NULL);
		}
		switch (query->op) {
		case OP_ANSWER:
			if (query->data.answer.answer_code == REPLY_ERROR) {
				*err_msg =
				    strdup(query->data.answer.answer_msg);
				close(socket);
				if (all_session)
					bdd_session_free(all_session);
				return (NULL);
			}
			else if (query->data.answer.answer_code != REPLY_OK) {
				log(LOG_WARNING,
				    "invalide answer_code in read_answer_switch"
				    " : must be %1$s_ERROR or %1$s_OK",
				    display_type(type));
				if (err_msg)
					asprintf(err_msg, "invalide answer_code"
					    " in read_answer_switch : must be "
					    "%1$s_ERROR or %1$s_OK",
					    display_type(type));
				close(socket);
				if (all_session)
					bdd_session_free(all_session);
				return (NULL);
			}
			else {
				close(socket);
				return (all_session);
			}
			break;
		case OP_MSG_AUTH:
			if (type == AUTH || type == ISAUTH) {
				if (all_session)
					bdd_session_free(all_session);
				all_session = bdd_session_new(
				    query->data.auth.ip,
				    query->data.auth.user, 0, 0,
				    query->data.auth.expire_date,
				    query->data.auth.start_time, NULL);
			}
			else if (type == UNAUTH || type == LIST) {
				current = bdd_session_new(query->data.auth.ip,
				    query->data.auth.user, 0, 0,
				    query->data.auth.expire_date,
				    query->data.auth.start_time, all_session);
				if(!all_session)
					all_session = current;
			}
			else {
				log(LOG_WARNING,
				    "invalid type for op_code OP_MSG_AUTH in "
				    "read_answer_switch : must be AUTH, UNAUTH,"
				    " ISAUTH or LIST");
				if (err_msg)
					asprintf(err_msg,
					    "invalid type for op_code "
					    "OP_MSG_AUTH in read_answer_switch "
					    ": AUTH, UNAUTH, ISAUTH or LIST");
			}
			break;
		case OP_MSG_LOG:
			if (type == HISTO) {
				current = bdd_session_new(query->data.log.ip,
				     query->data.log.user,
				     query->data.log.type,
				     query->data.log.event_time, 0,
				     query->data.log.start_time, all_session);
				if (!all_session)
					all_session = current;
			}
			else {
				log(LOG_WARNING,
				    "invalid type for op_code OP_MSG_LOG in "
				    "read_answer_switch : must be HISTO");
				if (err_msg)
					asprintf(err_msg,
					    "invalid type for op_code "
					    "OP_MSG_LOG in read_answer_switch :"
					    " must be HISTO");
			}
			break;
		default:
			log(LOG_WARNING,
			    "invalid op_code in read_answer_switch : must be "
			    "OP_ANSWER, OP_MSG_AUTH or OP_MSG_LOG");
			if (err_msg)
				asprintf(err_msg,
				    "invalid op_code in read_answer_switch : "
				    "must be OP_ANSWER, OP_MSG_AUTH or "
				    "OP_MSG_LOG");
			close(socket);
			if (all_session)
				bdd_session_free(all_session);
			return (NULL);
			break;
		}
	} while(1);
}

session *auth(char *user, char *ip, char *password, auth_unauth_mode mode, 
    char **err_msg) {
	struct timeval start;
	int sock_client = -1;
	msg query;
	session *session_auth = NULL;

	switch (mode) {
	case mode_auto:
	case mode_socket:
		if (!(check_sock (&sock_client, &mode, err_msg))) {
			if (mode != mode_direct)
				return (NULL);
		}
		else if (sock_send_auth(sock_client, &query, user, ip, password,
		    err_msg)) {
			close(sock_client);
			return (NULL);
		}
		else {
			return (read_answer_switch(sock_client, &query, AUTH,
			    err_msg));
			break;
		}
	case mode_direct:
		if((session_auth = unauth(by_ip, ip, mode_direct, NULL)))
			bdd_session_free(session_auth);
		gettimeofday(&start, NULL);
		if (!bdd_insert(user, ip, err_msg) && fwl_auth(user, ip, start))
		{
			bdd_insert_log(user, ip, time(NULL), AUTH);
			session_auth = bdd_get_session_by_ip(ip, err_msg);
			return (session_auth);
		}
		return (NULL);
	break;
	default:
		log(LOG_WARNING, "mode error: invalid mode");
		if(err_msg)
			asprintf(err_msg, "mode error: invalid mode");
		return (NULL);
	}
	return (NULL);
}

session *unauth(flag_unauth flag, char *user_or_ip, auth_unauth_mode mode,
    char **err_msg) {

	struct timeval start;
	session *unauth_session = NULL, *current = NULL;
	int sock_client = -1;
	msg query;

	switch (mode) {
	case mode_auto:
	case mode_socket:
		if (!(check_sock (&sock_client, &mode, err_msg))) {
			if (mode != mode_direct)
				return (NULL);
		}
		else if(sock_send_unauth(sock_client, &query, flag, user_or_ip,
		    err_msg)) {
			close(sock_client);
			return (NULL);
		}
		else {
			return (read_answer_switch(sock_client, &query, UNAUTH,
			    err_msg));
			break;
		}
	case mode_direct:
		gettimeofday(&start, NULL);
		if (flag == by_user) {
			if ((unauth_session = bdd_get_session_by_user(
			    user_or_ip, err_msg))) {
				if (!unauth_session->head) {
					start.tv_sec =
					    unauth_session->start_time;
					start.tv_usec = 0;
					if (!bdd_delete(unauth_session->ip,
					    err_msg)) {
						bdd_insert_log(user_or_ip,
						    unauth_session->ip,
						    unauth_session->start_time,
						    UNAUTH);
						fwl_unauth(user_or_ip,
						    unauth_session->ip, start);
						return (unauth_session);
					}
					else {
						bdd_session_free(unauth_session);
						return (NULL);
					}
				}
				else {
					SLIST_FOREACH(current,
					    unauth_session->head, next) {
						start.tv_sec =
						    current->start_time;
						start.tv_usec = 0;
						if (!bdd_delete(current->ip,
						    err_msg)) {
						bdd_insert_log(user_or_ip,
						    current->ip,
						    current->start_time,
						    UNAUTH);
						fwl_unauth(user_or_ip,
						    current->ip, start);
						}
						else {
							bdd_session_free(
							    unauth_session);
							return (NULL);
						}
					}
					return (unauth_session);
				}
			}
		}
		else if (flag == by_ip) {
			if ((unauth_session = bdd_get_session_by_ip(user_or_ip,
			    err_msg))) {
				start.tv_sec = unauth_session->start_time;
				if (!bdd_delete(user_or_ip, err_msg)) {
					bdd_insert_log(unauth_session->user_name
					    , user_or_ip
					    , unauth_session->start_time
					    , UNAUTH);
					fwl_unauth(unauth_session->user_name,
					    user_or_ip, start);
					return (unauth_session);
				}
				else {
					bdd_session_free(unauth_session);
					return (NULL);
				}
			}
		}
		else {
			log(LOG_WARNING, "Invalid flag for unauth");
			if(err_msg)
				asprintf(err_msg, "Invalid flag for unauth");
		}
		return (NULL);
		break;
	default:
		log(LOG_WARNING, "mode error : invalid mode");
		if(err_msg)
			asprintf(err_msg, "mode error: invalid mode");
		return (NULL);
	}
	return (NULL);
}

session *isauth (char *ip, auth_unauth_mode mode, char **err_msg) {
	int sock_client = -1;
	session *isauth_session = NULL;
	msg query;

	switch (mode) {
	case mode_auto:
	case mode_socket:
		if (!(check_sock (&sock_client, &mode, err_msg))) {
			if (mode != mode_direct)
				return (NULL);
		}
		else if (sock_send_isauth(sock_client, &query, ip, err_msg)) {
			close(sock_client);
			return (NULL);
		}
		else {
			return (read_answer_switch(sock_client, &query, ISAUTH,
			    err_msg));
			break;
		}
	case mode_direct:
		isauth_session = bdd_get_session_by_ip(ip, err_msg);
		if (isauth_session != NULL) {
			return(isauth_session);
		}
		return (NULL);
	break;
	default:
		log(LOG_WARNING, "mode error : invalid mode");
		if (err_msg)
			asprintf(err_msg, "mode error : invalid mode");
		return (NULL);
	}
	return (NULL);
}

session *list_user(auth_unauth_mode mode, char **err_msg)
{
	int sock_client = -1;
	session *list = NULL;
	msg query;

	switch (mode) {
	case mode_auto:
	case mode_socket:
		if (!(check_sock (&sock_client, &mode, err_msg))) {
			if (mode != mode_direct)
				return (NULL);
		}
		else if (sock_send_list_user(sock_client, &query, err_msg)) {
			close(sock_client);
			return (NULL);
		}
		else {
			return (read_answer_switch(sock_client, &query, LIST,
			    err_msg));
			break;
		}
	case mode_direct:
		list = bdd_get_list_user(err_msg);
		return(list);
	break;
	default:
		log(LOG_WARNING, "mode error : invalid mode");
		if (err_msg)
			asprintf(err_msg, "mode error : invalid mode");
		return (NULL);
	}
	return (NULL);
}

session *log_histo(time_t date, auth_unauth_mode mode, char **err_msg)
{
	int sock_client = -1;
	session *histo = NULL;
	msg query;

	log(LOG_DEBUG, "log_histo(%d)", date);

	switch (mode) {
	case mode_auto:
	case mode_socket:
		if (!(check_sock (&sock_client, &mode, err_msg))) {
			if (mode != mode_direct)
				return (NULL);
		}
		else if (sock_send_log_histo(sock_client, &query, date,
		    err_msg)) {
			close(sock_client);
			return (NULL);
		}
		else {
			return (read_answer_switch(sock_client, &query, HISTO,
			    err_msg));
			break;
		}
	case mode_direct:
		histo = bdd_get_histo(date, err_msg);
		return(histo);

	break;
	default:
		log(LOG_WARNING, "mode error : invalid mode");
		if (err_msg)
			asprintf(err_msg, "mode error : invalid mode");
		return (NULL);
	}
	return (NULL);
}

int send_ping(char **err_msg) {
	int sock_client = -1;
	msg query;

	if ((sock_client = socket_client(conf_socket_path, err_msg)) == -1) {
			log(LOG_WARNING, "Invalid socket");
			return (0);
	}
	else if (sock_send_ping(sock_client, &query, err_msg)) {
		close(sock_client);
		return (0);
	}
	else {
		if (sock_read_msg(sock_client, &query, err_msg)) {
			log(LOG_WARNING, "read message error %s", *err_msg);
			close(sock_client);
			return (0);
		}
		else if (query.op == OP_PONG) {
			close(sock_client);
			return (1);
		}
		else {
			log(LOG_WARNING,
			    "invalide op %d in send_ping : must be "
			    "OP_PONG(%d)-REPLY_OK(%d)", query.op, OP_PONG);
			close(sock_client);
			return (0);
		}
	}
	return (0);
}
