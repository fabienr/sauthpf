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
#define LOG_C

#include "compat.h"

#include <syslog.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "log.h"
#include "conf.h"

void log_init(const char *subsys, int verbose, bool arg_debug)
{
	openlog(subsys, LOG_PID /*| LOG_PERROR*/, LOG_DAEMON);
	if (verbose == 0)
		setlogmask(LOG_UPTO(LOG_WARNING));
	else if (verbose == 1)
		setlogmask(LOG_UPTO(LOG_INFO));
	else if (verbose == 2)
		setlogmask(LOG_UPTO(LOG_DEBUG));
	else 
		setlogmask(LOG_UPTO(LOG_WARNING));
	debug = arg_debug;
}

void log_quit(void)
{
	closelog();
}

void log_write(const char *file, int line_nb, int level, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	if (debug == false)
		vsyslog(level, fmt, ap);
	else {
		char *str;
		if (asprintf(&str, "[%s:%d] %s\n",  file, line_nb, fmt) > 0) {
			vsyslog(level, str, ap);
			va_end(ap);
			va_start(ap, fmt);
			vfprintf(stderr, str, ap);
			free(str);
		}
		else {
			syslog(LOG_WARNING, "asprintf error : %m");
		}
	}
	va_end(ap);
}
