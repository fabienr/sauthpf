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

#ifdef HAVE_PF
#include "../firewall/pf.h"
#endif

#ifdef HAVE_IPTABLE
#include "../firewall/ipt.h"
#endif

#include <sys/time.h>

#include "log.h"

void fwl_quit(void)
{
#ifdef HAVE_PF
	pf_quit();
#endif
}

int fwl_init(void)
{
#if defined (HAVE_PF)
	return(pf_init());

#elif defined (HAVE_IPTABLE)
	log(LOG_INFO, "iptable");
	return(true);
#else
	log(LOG_INFO, "fwl_init : No firewall define at compilation.");
	return(true);
#endif
}

bool fwl_auth(const char *user, const char *ip, struct timeval start)
{
#if defined (HAVE_PF)
	return(pf_auth(user, ip, start));
#elif defined (HAVE_IPTABLE)
	log(LOG_INFO, "iptable");
	return(true);
#else
	return(true);
#endif
}

void fwl_unauth(const char *user, const char *ip, struct timeval start)
{
#if defined (HAVE_PF)
	pf_unauth(user, ip, start);
#elif defined (HAVE_IPTABLE)
	log(LOG_INFO, "iptable");
#endif
}
