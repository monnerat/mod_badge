/**
***	mod_badge: various support procedures.
***
***	Copyright (c) 2011-2015 Datasphere S.A.
***	Copyright (c) 2015-2016 D+H
***	Copyright (c) 2017 Patrick Monnerat
***
***	Licensed under the Apache License, Version 2.0 (the "License");
***	you may not use this file except in compliance with the License.
***	You may obtain a copy of the License at
***
***		http://www.apache.org/licenses/LICENSE-2.0
***
***	Unless required by applicable law or agreed to in writing, software
***	distributed under the License is distributed on an "AS IS" BASIS,
***	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
***	See the License for the specific language governing permissions and
***	limitations under the License.
**/

#include <stdarg.h>

#include "mod_badge.h"



static int
badge_canonicalize_path_recursive(char * * ptrfrom, char * * ptrto)

{
	char * from;
	char * to;
	int i;

	to = *ptrto;
	*to = '/';

	for (;;) {
		*ptrto = to;

		for (from = *ptrfrom; *from == '/'; from++)
			;

		*ptrfrom = from;

		if (!*from)
			break;

		for (i = 0; from[i] && from[i] != '/'; i++)
			;

		if (*from == '.')
			switch (i) {

			case 1:
				*ptrfrom = from + i;
				continue;

			case 2:
				if (from[1] != '.')
					break;

				*ptrfrom = from + i;
				return -1;
				}

		memmove(to + 1, from, i);
		*ptrto = to + i + 1;
		*ptrfrom = from + i;

		if (!badge_canonicalize_path_recursive(ptrfrom, ptrto))
			break;
		}

	return 0;
}


const char *
badge_canonicalize_path(apr_pool_t * p, const char * curdir, const char * path)

{
	char * res;
	char * fm;
	char * to;

	/**
	***	Canonicalize path and prepend `curdir' if relative.
	**/

	if (!curdir)
		curdir = "";

	res = apr_pstrcat(p, "/", curdir, "/", path, NULL);
	fm = res;
	to = res;
	badge_canonicalize_path_recursive(&fm, &to);

	if (to == res)
		to++;

	*to = '\0';
	return res;
}


const char *
badge_match_prefix(const char * uri, const char * prefix)

{
	/**
	***	Try matching the given prefix with the uri. Skip multiple
	***		slashes while doing it.
	***	Return a pointer to the first unmatched component in uri, or
	***		NULL if no match.
	**/

	for (;;) {
		while (*uri == '/')
			uri++;

		while (*prefix == '/')
			prefix++;

		if (!*prefix)
			break;

		for (;;) {
			if (!*prefix || *prefix == '/')
				break;

			if (*uri != *prefix)
				return NULL;

			uri++;
			prefix++;
			}

		if (*uri && *uri != '/')
			return NULL;
		}

	return uri;
}


apr_array_header_t *
badge_unique_key_files(apr_pool_t * pool, badge_conf * conf)

{
	apr_array_header_t * keys;
	badge_entry * fb;
	badge_entry * fe;
	badge_entry * * tp;

	/**
	***	Get the list of unique key files.
	**/

	keys = apr_array_make(pool, 5, sizeof(badge_entry * *));
	fb = (badge_entry *) conf->badges->elts;

	for (fe = fb + conf->badges->nelts; fb < fe; fb++) {
		if (!fb->key)
			continue;	/* Did not get a key from it. */

		tp = apr_array_push(keys);
		*tp = fb;

		for (tp = (badge_entry * *) keys->elts;
		    strcmp((*tp)->sslfile, fb->sslfile); tp++)
			;

		if ((badge_entry * *) keys->elts + keys->nelts - tp != 1)
			keys->nelts--;
		}

	return keys;
}


int
badge_load_key(badge_entry * e)

{
	void * key;
	int keylen;
	int isprivate;

	/**
	***	Load crypt key for the given badge entry.
	**/

	/* Try private key first. */

	key = badge_read_PrivateKey(e->sslfile, &keylen);
	isprivate = key != NULL;

	if (!isprivate) {
		/* Then try certificate. */

		key = badge_read_PublicKey_from_X509_cert(e->sslfile, &keylen);

		if (!key)	/* Then try for a public key alone. */
			key = badge_read_PublicKey(e->sslfile, &keylen);
		}

	if (!key)
		return 0;

	if (e->key)
		badge_free_key(e->key, e->isprivate);

	e->key = key;
	e->keylen = keylen;
	e->isprivate = isprivate;
	return 1;
}


/* VARARGS6 */
void
badge_log_perror(const char * file, int line, int level,
		apr_status_t status, apr_pool_t * p, const char *fmt, ...)

{
	char errstr[MAX_STRING_LEN];
	va_list ap;

	va_start(ap, fmt);
	apr_vsnprintf(errstr, sizeof errstr, fmt, ap);
	va_end(ap);

#if HTTP_VERSION(AP_SERVER_MAJORVERSION_NUMBER,				\
			AP_SERVER_MINORVERSION_NUMBER) >= HTTP_VERSION(2, 4)
	ap_log_perror(file, line, APLOG_MODULE_INDEX, level, status, p,
	    "%s", errstr);
#else
	ap_log_perror(file, line, level, status, p, "%s", errstr);
#endif
}
