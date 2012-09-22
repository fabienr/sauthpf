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

#define SOCK_C

 #include "compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
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
#include "log.h"
#include "sock.h"

#define BUFF_MAX_SIZE 128

int socket_server (char *socket_path)
{
	struct sockaddr_un sockad;
	socklen_t len;
	int sock = -1;

	sockad.sun_family = AF_UNIX;
	strlcpy(sockad.sun_path, socket_path, sizeof(sockad.sun_path));

	unsigned int path_len = strlen(socket_path);
	if (path_len>= sizeof(sockad.sun_path)) {
		log(LOG_WARNING, "listening socket's path name (%s) is too "
		    "long : %m", socket_path);
		goto error;
	}
	len = (size_t)(((struct sockaddr_un *)0)->sun_path) + path_len;

	if ((sock = socket(sockad.sun_family, SOCK_STREAM , 0)) < 0) {
		log(LOG_WARNING, "socket error on %s : %m", socket_path);
		goto error;
	}
	unlink(socket_path);
	if (bind(sock, (struct sockaddr *) &sockad, len) < 0) {
		log(LOG_WARNING, "bind error on %s : %m", socket_path);
		goto error;
	}
	if (listen(sock, 128) < 0) {
		log(LOG_WARNING, "listen error on %s : %m", socket_path);
		goto error;
	}
	sock_server = sock;
	if (chmod(socket_path, 00770) == -1) {
		log(LOG_WARNING, "chmod error on %s : %m",
		    socket_path);
		goto error;
	}
	log(LOG_DEBUG, "listning on %s", socket_path);
	return (sock);

	error:
	if (sock)
		close(sock);
	return (-1);
}

void close_socket_server(void)
{
	if (sock_server >= 0) {
		close(sock_server);
	}
}

int socket_client (char *socket_path, char **err_msg)
{
	struct sockaddr_un sockad;
	int sock= -1;

	sockad.sun_family = AF_UNIX;
	strlcpy(sockad.sun_path, socket_path, sizeof(sockad.sun_path));

	if ((sock = socket(sockad.sun_family, SOCK_STREAM , 0)) < 0) {
		log(LOG_WARNING, "socket error on %s : %m", socket_path);
		if (err_msg)
			asprintf(err_msg, "socket error on %s : %s",
			    socket_path, strerror(errno));
		goto error;
	}
	else if (connect(sock, (struct sockaddr *)&sockad, sizeof sockad) < 0) {
		log(LOG_WARNING, "connect error on %s : %m", socket_path);
		if (err_msg)
			asprintf(err_msg, "connect error on %s : %s",
			    socket_path, strerror(errno));
		 goto error;
	}
	return (sock);

error:
	if (sock)
		close(sock);
	return (-1);
}

int sock_read_msg(int socket, msg *message, char **err_msg)
{
	ssize_t s;

	if ((s = read(socket, message, sizeof(msg))) < 0) {
		log(LOG_WARNING, "read error : %m");
		if (err_msg)
			asprintf(err_msg, "read error in sock_read_msg: %s",
			    strerror(errno));
		return (1);
	}
	else if (s == 0) {
		log(LOG_WARNING, "sokcet is close in sock_read_msg");
		if (err_msg)
			asprintf(err_msg, "socket is close in sock_read_msg");
		return (1);
	}
	else if (s != sizeof(msg)) {
		log(LOG_WARNING, "invalid message in sock_read_msg : "
		    "read only %d bytes instead of %d excpected "
		    "in sock_read_msg", s, sizeof(msg));
		if (err_msg)
			asprintf(err_msg, "invalid message in "
			    "sock_read_msg : read only %d bytes instead of %d "
			    "excpected in sock_read_msg", (int)s,
			    (int)sizeof(msg));
		return (1);
	}
	else if (message->version > SAUTHPF_PROTO_VERSION) {
		log(LOG_WARNING, "invalid version in sock_read_msg");
		if (err_msg)
			asprintf(err_msg, "invalid version in sock_read_msg");
		return (1);
	}
	else if (message->op > MAX_OP_CODE || message->op < 0) {
		log(LOG_WARNING, "invalid operation code in sock_read_msg");
		if (err_msg)
			asprintf(err_msg, "invalid operation code in "
			    "sock_read_msg");
		return (1);
	}
	else if (message->op == OP_ANSWER && (
	    message->data.answer.answer_code < 0 ||
	    message->data.answer.answer_code > MAX_REPLY_CODE)) {
		log(LOG_WARNING, "invalid reply code in sock_read_msg");
		if (err_msg)
			asprintf(err_msg, "invalid reply code in sock_read_msg");
		return (1);
	}

	/* ensure \0 at end of string for security */
	switch (message->op) {
	case OP_ANSWER:
		message->data.answer.answer_msg[
		    sizeof(message->data.answer.answer_msg)-1] = '\0';
		break;
	case OP_AUTH:
	case OP_UNAUTH:
	case OP_ISAUTH:
	case OP_MSG_AUTH:
		message->data.auth.user[
		    sizeof(message->data.auth.user)-1] = '\0';
		message->data.auth.ip[
		    sizeof(message->data.auth.ip)-1] = '\0';
		message->data.auth.password[
		    sizeof(message->data.auth.password)-1] = '\0';
	break;
	case OP_HISTO:
	case OP_MSG_LOG:
		message->data.log.user[sizeof(message->data.log.user)-1]
		    = '\0';
		message->data.log.ip[sizeof(message->data.log.ip)-1] = '\0';
	break;
	case OP_PING:
	case OP_PONG:
	case OP_LIST:
	break;
	default:
		log(LOG_WARNING, "invalid op_code in sock_read_msg");
		if (err_msg)
			asprintf(err_msg, "invalid operation code in "
			    "sock_read_msg");
		return(1);
	break;
	}

	return (0);
}

int sock_send_msg(int socket, msg *message, char **err_msg)
{
	ssize_t s;

	if ((s = write(socket, message, sizeof(msg))) < 0) {
		log(LOG_WARNING, "write error in sock_send_msg : %m");
		if (err_msg)
			asprintf(err_msg, "write error in sock_send_msg: %s",
			    strerror(errno));
		return (1);
	}
	else if (s == 0) {
		log(LOG_WARNING, "sokcet is close in sock_send_msg");
		if (err_msg)
			asprintf(err_msg, "socket is close in sock_send_msg");
		return (1);
	}
	else if (s != sizeof(msg)) {
		log(LOG_WARNING, "cannot write message in sock_send_msg : "
		    "%d write instead of %d expected", s, sizeof(msg));
		if (err_msg)
			asprintf(err_msg, "cannot write message in "
			    "sock_send_msg : %d write instead of %d expected",
			     (int)s, (int)sizeof(msg));
		return (1);
	}
	return (0);
}

int sock_send_auth(int socket, msg *query, char *user, char *ip, char *password,
     char **err_msg) {
	memset(query, 0, sizeof(msg));
	query->version = SAUTHPF_PROTO_VERSION;
	query->op = OP_AUTH;
	strlcpy(query->data.auth.user, user, sizeof(query->data.auth.user));
	strlcpy(query->data.auth.ip, ip, sizeof(query->data.auth.ip));
	if (password)
		strlcpy(query->data.auth.password, password,
		    sizeof(query->data.auth.password));
	if (sock_send_msg(socket, query, err_msg))
		return (1);
	return 0;
}

int sock_send_unauth(int socket, msg *query, flag_unauth flag, char *user_or_ip,
    char **err_msg)
{
	memset(query, 0, sizeof(msg));
	query->version = SAUTHPF_PROTO_VERSION;
	query->op = OP_UNAUTH;
	strlcpy(query->data.unauth.user_or_ip, user_or_ip,
	    sizeof(query->data.unauth.user_or_ip));
	query->data.unauth.flag = flag;
	if (sock_send_msg(socket, query, err_msg))
		return (1);
	return (0);
}

int sock_send_isauth(int socket, msg *query, char *ip, char **err_msg)
{
	memset(query, 0, sizeof(msg));
	query->version = SAUTHPF_PROTO_VERSION;
	query->op = OP_ISAUTH;
	strlcpy(query->data.auth.ip, ip, sizeof(query->data.auth.ip));
	if (sock_send_msg(socket, query, err_msg))
		return (1);
	return 0;
}

int sock_send_list_user(int socket, msg *query, char **err_msg)
{
	memset(query, 0, sizeof(msg));
	query->version = SAUTHPF_PROTO_VERSION;
	query->op = OP_LIST;
	if (sock_send_msg(socket, query, err_msg))
		return (1);
	return 0;
}

int sock_send_log_histo(int socket, msg *query, time_t date,char **err_msg)
{
	memset(query, 0, sizeof(msg));
	query->version = SAUTHPF_PROTO_VERSION;
	query->op = OP_HISTO;
	query->data.log.start_time = date;
	if (sock_send_msg(socket, query, err_msg))
		return (1);
	return 0;
}

int sock_send_ping(int socket, msg *query, char **err_msg)
{
	memset(query, 0, sizeof(msg));
	query->op = OP_PING;
	query->version = SAUTHPF_PROTO_VERSION;
	if (sock_send_msg(socket, query, err_msg))
		return (1);
	return (0);
}

int sock_send_reply(int socket, int reply_code, char *reply, ...)
{
	msg mess;
	char *ans;
	memset(&mess, 0, sizeof(msg));
	va_list ap;

	va_start(ap, reply);
	if (vasprintf(&ans, reply, ap) < 0) {
		log(LOG_WARNING, "vasprintf error : %m");
		va_end(ap);
		return (1);
	}
	va_end(ap);
	mess.op = OP_ANSWER;
	mess.version = SAUTHPF_PROTO_VERSION;
	mess.data.answer.answer_code = reply_code;
	strlcpy(mess.data.answer.answer_msg, ans,
	    sizeof(mess.data.answer.answer_msg));
	free(ans);
	if (sock_send_msg(socket, &mess, NULL))
		return (1);
	return (0);
}

int sock_send_msg_auth(int socket, session *session_reply)
{
	msg reply;
	memset(&reply, 0, sizeof(msg));
	reply.op = OP_MSG_AUTH;
	reply.version = SAUTHPF_PROTO_VERSION;
	reply.data.auth.start_time = session_reply->start_time;
	reply.data.auth.expire_date = session_reply->expire_date;
	strlcpy(reply.data.auth.ip, session_reply->ip,
	    sizeof(reply.data.auth.ip));
	strlcpy(reply.data.auth.user, session_reply->user_name,
	    sizeof(reply.data.auth.user));
	if (sock_send_msg(socket, &reply, NULL))
		return (1);
	return (0);
}

int sock_send_msg_log(int socket, session *session_reply)
{
	msg reply;
	memset(&reply, 0, sizeof(msg));
	reply.op = OP_MSG_LOG;
	reply.version = SAUTHPF_PROTO_VERSION;
	reply.data.log.start_time = session_reply->start_time;
	reply.data.log.event_time = session_reply->event_time;
	reply.data.log.type = session_reply->type;
	strlcpy(reply.data.log.ip, session_reply->ip,
	    sizeof(reply.data.log.ip));
	strlcpy(reply.data.log.user, session_reply->user_name,
	    sizeof(reply.data.log.user));
	if (sock_send_msg(socket, &reply, NULL))
		return (1);
	return (0);
}

int sock_read_query(int socket_serveur, msg *message)
{
	int sock_client = -1;
	socklen_t len;
	struct sockaddr_un sockad;

	len = sizeof(sockad);
	while (!end_process) {
		if ((sock_client = accept(socket_serveur,
		    (struct sockaddr *)&sockad, &len)) == -1) {
			log(LOG_WARNING, "accept error : %m");
			return (-1);
		}
		in_action = true;
		if (sock_read_msg(sock_client, message, NULL)) {
			in_action = false;
			return(-1);
		}
		else {
			if (message->op == OP_PING) {
				message->op = OP_PONG;
				sock_send_msg(sock_client, message, NULL);
			}
			else {
				in_action = false;
				return(sock_client);
			}
		}
		in_action = false;
	}
	close(sock_client);
	return(-1);
}
