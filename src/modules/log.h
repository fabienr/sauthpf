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
#ifndef LOG_H
#define LOG_H

#include <syslog.h>
#include <stdarg.h>
#include "bool.h"

void log_init(const char *, int, bool);
void log_quit(void);
void log_write(const char *, int, int, const char *, ...);

#define log(fmt, ...)	log_write(__FILE__, __LINE__, fmt, __VA_ARGS__)

#ifdef LOG_C
static bool debug;
#endif

#endif
