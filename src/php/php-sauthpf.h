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
#ifndef PHP_SAUTHPF_H
#define PHP_SAUTHPF_H 1

#define PHP_SAUTHPF_VERSION "0.1"

ZEND_FUNCTION(sauthpf_init);
ZEND_FUNCTION(sauthpf_auth);
ZEND_FUNCTION(sauthpf_unauth);
ZEND_FUNCTION(sauthpf_isauth);
ZEND_FUNCTION(sauthpf_list_user);
ZEND_FUNCTION(sauthpf_log_histo);

ZEND_MINFO_FUNCTION(sauthpf);

extern zend_module_entry sauthpf_module_entry;
#define phpext_sauthpf_ptr &sauthpf_module_entry

#endif
