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

#include <stdio.h>
#include <stdlib.h>

#ifndef DISABLE_SAUTH
#include <login_cap.h>
#include <bsd_auth.h>
#endif

#include "secure_auth.h"
#include "log.h"

int sauth(char *user, char *password)
{
	#ifndef DISABLE_SAUTH
	if ((auth_userokay(user, NULL, NULL, password)) == 0) {
		log(LOG_INFO, "auth_userokay error");
		return (1);
	}
	return (0);
	#else
	log(LOG_WARNING, "secure_auth is enable but your system isn't "
	    "compatible\n");
	return (1);
	#endif
}
