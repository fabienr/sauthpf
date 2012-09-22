/*
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "Zend/zend_exceptions.h"
#include "ext/standard/info.h"
#include "php-sauthpf.h"
#include "modules/conf.h"
#include "modules/log.h"
#include "modules/users.h"

#include <stdio.h>

#ifndef DEFAULT_CONF_FILE
#define DEFAULT_CONF_FILE	"/etc/sauthpf/sauthpf.conf"
#endif

#define SUBSYS			"sauthpf-php"

static int init = 0;

static zval *_sessions_to_zval(session *);

/* {{{ php_gettext_functions[] */
static zend_function_entry sauthpf_functions[] = {
	ZEND_FE(sauthpf_init,		NULL)
	ZEND_FE(sauthpf_auth,		NULL)
	ZEND_FE(sauthpf_unauth,		NULL)
	ZEND_FE(sauthpf_isauth,		NULL)
	ZEND_FE(sauthpf_list_user,	NULL)
	ZEND_FE(sauthpf_log_histo,	NULL)
	{NULL, NULL, NULL}
};
/* }}} */

zend_module_entry sauthpf_module_entry = {
	STANDARD_MODULE_HEADER,
	"sauthpf",
	sauthpf_functions,
	NULL,
	NULL,
	NULL,
	NULL,
	ZEND_MINFO(sauthpf),
	NO_VERSION_YET,
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_SAUTHPF
ZEND_GET_MODULE(sauthpf)
#endif

ZEND_MINFO_FUNCTION(sauthpf)
{
	php_info_print_table_start();
	php_info_print_table_row(2, "Module Version", PHP_SAUTHPF_VERSION);
	php_info_print_table_row(2, "Socket Path", conf_socket_path);
	php_info_print_table_row(2, "Serveur PID file path", conf_pid_path);
	php_info_print_table_end();
}

/* {{{ proto bool sauthpf_init(string conf_file)
   Init sauthpf. Returns the bool */
ZEND_FUNCTION(sauthpf_init)
{
	char *conf_file;
	int conf_file_len;

	if (init)
		RETURN_TRUE;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
	    &conf_file, &conf_file_len) == FAILURE) {
		conf_file = DEFAULT_CONF_FILE;
	}

	log_init(SUBSYS, 0, 0);
	log(LOG_DEBUG, "using configuration file '%s'", conf_file);
	if (load_config(conf_file) != 0) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "sauthpf_init error, see syslog");
		RETURN_FALSE;
	}

	init = 1;
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool sauthpf_auth(string user, string ip)
   Auth user in sauthpf. Returns the session or false */
ZEND_FUNCTION(sauthpf_auth)
{
	char *user, *ip, *password = NULL, *err_msg;
	int user_len, ip_len, password_len;
	session *session_auth;
	zval *array;

	if (ZEND_NUM_ARGS() == 2) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
		    &user, &user_len, &ip, &ip_len) == FAILURE) {
			php_error_docref(NULL TSRMLS_CC, E_ERROR,
			    "Could not auth user");
			RETURN_FALSE;
		}
	}
	else if (ZEND_NUM_ARGS() == 3) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
		    &user, &user_len, &ip, &ip_len, &password, &password_len)
		    == FAILURE) {
			php_error_docref(NULL TSRMLS_CC, E_ERROR,
			    "Could not auth user");
			RETURN_FALSE;
		}
	}
	else {
		php_error_docref(NULL TSRMLS_CC, E_ERROR,
		    "Could not auth user : sauthpf_auth take 2 or 3 arguments, "
		    "only %d given", ZEND_NUM_ARGS());
		RETURN_FALSE;
	}

	if (init!=1) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING,
		    "sauthpf_init must be call before");
		RETURN_FALSE;
	}

	if ((session_auth = auth(user, ip, password, mode_socket, &err_msg))
	    == NULL) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING,
		    "sauthpf_auth error : %s", err_msg);
		free(err_msg);
		RETURN_FALSE;
	}
	array = _sessions_to_zval(session_auth);
	bdd_session_free(session_auth);

	RETURN_ZVAL(array, 0, 1);
}
/* }}} */

/* {{{ proto bool sauthpf_unauth(string user_or_ip, int flag)
 * flag : O == user, 1 == ip
 * Unauth user in sauthpf. Returns the session or false
 */
ZEND_FUNCTION(sauthpf_unauth)
{
	char *user_or_ip, *err_msg;
	int user_or_ip_len, flag;
	session *session_unauth;
	zval *array;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sd",
	    &user_or_ip, &user_or_ip_len, &flag) == FAILURE) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR,
		    "Could not unauth user");
		RETURN_FALSE;
	}

	if (init!=1) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING,
		    "sauthpf_init must be call before");
		RETURN_FALSE;
	}

	if (flag) {
		if ((session_unauth = unauth(by_user, user_or_ip, mode_socket,
		    &err_msg)) == NULL) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING,
			    "sauthpf_unauth error : %s", err_msg);
			free(err_msg);
			RETURN_FALSE;
		}
		array = _sessions_to_zval(session_unauth);
		bdd_session_free(session_unauth);
	}
	else {
		if ((session_unauth = unauth(by_ip, user_or_ip, mode_socket,
		    &err_msg)) == NULL) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING,
			    "sauthpf_unauth error : %s", err_msg);
			free(err_msg);
			RETURN_FALSE;
		}
		array = _sessions_to_zval(session_unauth);
		bdd_session_free(session_unauth);
	}
	RETURN_ZVAL(array, 0, 1);
}
/* }}} */

/* {{{ proto bool sauthpf_isauth(string ip)
   Check if ip is auth in sauthpf. Returns the session or false */
ZEND_FUNCTION(sauthpf_isauth)
{
	char *ip, *err_msg = NULL;
	int ip_len;
	session *session_isauth;
	zval *array;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
	    &ip, &ip_len) == FAILURE) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR,
		    "Could not test auth ip");
		RETURN_FALSE;
	}

	if (init!=1) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING,
		    "sauthpf_init must be call before");
		RETURN_FALSE;
	}

	if ((session_isauth = isauth(ip, mode_socket, &err_msg)) == NULL) {
		if (err_msg) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING,
			    "sauthpf_isauth error : %s", err_msg);
			free(err_msg);
		}
		RETURN_FALSE;
	}
	array = _sessions_to_zval(session_isauth);
	bdd_session_free(session_isauth);

	RETURN_ZVAL(array, 0, 1);
}
/* }}} */

/* {{{ proto bool sauthpf_list_user()
   List auth user in sauthpf. Returns the sessions or false */
ZEND_FUNCTION(sauthpf_list_user)
{
	char  *err_msg = NULL;
	session *session_list;
	zval *array;
	
	if (init!=1) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING,
		    "sauthpf_init must be call before");
		RETURN_FALSE;
	}

	if ((session_list = list_user(mode_socket, &err_msg)) == NULL) {
		if (err_msg) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING,
			    "sauthpf_isauth error : %s", err_msg);
			free(err_msg);
		}
		RETURN_FALSE;
	}
	array = _sessions_to_zval(session_list);
	bdd_session_free(session_list);

	RETURN_ZVAL(array, 0, 1);
}
/* }}} */

/* {{{ proto bool sauthpf_log_histo(time_t date)
   Display logs. Returns the sessions or false */
ZEND_FUNCTION(sauthpf_log_histo)
{
	char  *err_msg = NULL;
	long arg;
	time_t date;
	session *session_log_histo;
	zval *array;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l",
	    &arg) == FAILURE) {
		php_error_docref(NULL TSRMLS_CC, E_ERROR,
		    "Could not parse date, integer required");
		RETURN_FALSE;
	}
	date = (time_t)arg;

	if (init!=1) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING,
		    "sauthpf_init must be call before");
		RETURN_FALSE;
	}

	if ((session_log_histo = log_histo(date, mode_socket, &err_msg)) == NULL) {
		if (err_msg) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING,
			    "log_histo error : %s", err_msg);
			free(err_msg);
		}
		RETURN_FALSE;
	}
	array = _sessions_to_zval(session_log_histo);
	bdd_session_free(session_log_histo);

	RETURN_ZVAL(array, 0, 1);
}
/* }}} */

static zval *_sessions_to_zval(session *sessions)
{
	session *current;
	zval *array, *return_session;
	ALLOC_ZVAL(array);
	array_init(array);
	INIT_PZVAL(array);

	if (sessions->head) {

		SLIST_FOREACH(current, sessions->head, next) {
			ALLOC_ZVAL(return_session);
			array_init(return_session);
			INIT_PZVAL(return_session);

			add_assoc_string(return_session, "user", current->user_name, 1);
			add_assoc_string(return_session, "ip", current->ip, 1);
			add_assoc_long(return_session, "type", current->type);
			add_assoc_long(return_session, "start_time", current->start_time);
			add_assoc_long(return_session, "event_time", current->event_time);
			add_next_index_zval(array, return_session);
		}
	}
	else {
		ALLOC_ZVAL(return_session);
		array_init(return_session);
		INIT_PZVAL(return_session);

		add_assoc_string(return_session, "user", sessions->user_name, 1);
		add_assoc_string(return_session, "ip", sessions->ip, 1);
		add_assoc_long(return_session, "type", sessions->type);
		add_assoc_long(return_session, "start_time", sessions->start_time);
		add_assoc_long(return_session, "event_time", sessions->event_time);
		add_next_index_zval(array, return_session);
	}

	return (array);
}

