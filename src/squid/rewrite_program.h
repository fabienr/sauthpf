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
#ifndef REWRITE_PROGRAM_H
#define REWRITE_PROGRAM_H

#include "../modules/bool.h"

bool rewrite_program_write(const char *);
char *rewrite_program_read(void);

void program_engine_quit(void);

#ifdef REWRITE_PROGRAM_C

#define MAX_BUF 1024

#define CHILD 0
#define PARENT 1

#define PIPE_READ 0
#define PIPE_WRITE 1

static pid_t pid = -1;
static int stdout_fd[2];
static int stdin_fd[2];

#define HELLO_BUF_SZ 32
static const char *hello_string = "hi there\n";
static char hello_buf[HELLO_BUF_SZ];

static bool program_execute(bool);

#endif

#endif
