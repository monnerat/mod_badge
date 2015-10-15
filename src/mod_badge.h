/**
***	mod_badge: definitions and prototypes.
***
***	Copyright (c) 2011-2015 Datasphere S.A.
***	Copyright (c) 2015 D+H
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

#ifndef _MOD_BADGE_H_
#define _MOD_BADGE_H_

#include <sys/types.h>

/**
***	Avoid package redefinitions from httpd include files.
**/

#ifdef PACKAGE_NAME
#define MOD_PACKAGE_NAME	PACKAGE_NAME
#undef PACKAGE_NAME
#endif

#ifdef PACKAGE_TARNAME
#define MOD_PACKAGE_TARNAME	PACKAGE_TARNAME
#undef PACKAGE_TARNAME
#endif

#ifdef PACKAGE_VERSION
#define MOD_PACKAGE_VERSION	PACKAGE_VERSION
#undef PACKAGE_VERSION
#endif

#ifdef PACKAGE_STRING
#define MOD_PACKAGE_STRING	PACKAGE_STRING
#undef PACKAGE_STRING
#endif

#ifdef PACKAGE_BUGREPORT
#define MOD_PACKAGE_BUGREPORT	PACKAGE_BUGREPORT
#undef PACKAGE_BUGREPORT
#endif

#ifdef PACKAGE_URL
#define MOD_PACKAGE_URL		PACKAGE_URL
#undef PACKAGE_URL
#endif


#define CORE_PRIVATE		1

#include <sys/types.h>

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"


#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_base64.h"
#include "apr_memcache.h"
#include "apr_lib.h"
#include "apr_time.h"
#include "apr_portable.h"



#define SEED_LEN_0		12	/* Crypto seed length (version 0). */

#define BADGE_URI		"mod_badge_uri"


/**
***	Badge data.
**/

typedef struct {
	int		version;	/* Data format version. */
	time_t		from;		/* Validity start timestamp. */
	time_t		to;		/* Validity end timestamp. */
	const char *	path;		/* Path prefix replacement. */
	const char *	user;		/* User name. */
	const char *	passwd;		/* Password. */
}		badge_data;


/**
***	Badge definition entry.
**/

typedef struct {
	const char *		fake;		/* Fake URL prefix. */
	const char *		sslfile;	/* SSL cert/key file name. */
	void *			key;		/* Public or private key. */
	int			keylen;		/* Key length (# bytes). */
	unsigned char		isprivate;	/* True if private key. */
}		badge_entry;


/**
***	Badge per-directory configuration.
**/

typedef struct {
	int			keepauth;	/* Keep user authorization. */
	apr_array_header_t *	badges;		/* Defined badges. */
}		badge_conf;


/**
***	Badge factory argument flags.
**/

#define BADGE_FROM_YEAR		0000001
#define BADGE_FROM_MONTH	0000002
#define BADGE_FROM_DAY		0000004
#define BADGE_FROM_HOUR		0000010
#define BADGE_FROM_MIN		0000020
#define BADGE_FROM_SEC		0000040
#define BADGE_TO_YEAR		0000100
#define BADGE_TO_MONTH		0000200
#define BADGE_TO_DAY		0000400
#define BADGE_TO_HOUR		0001000
#define BADGE_TO_MIN		0002000
#define BADGE_TO_SEC		0004000
#define BADGE_KEY_FILE		0010000
#define BADGE_PATH_PREFIX	0020000
#define BADGE_USERNAME		0040000
#define BADGE_PASSWORD		0100000


/**
***	Internal timestamp storage.
**/

typedef struct {
	const char *	year;
	const char *	month;
	const char *	day;
	const char *	hour;
	const char *	min;
	const char *	sec;
}		badge_timestamp;


/**
***	Global storage.
**/

extern module AP_MODULE_DECLARE_DATA	badge_module;


/**
***	Prototypes.
**/

extern void *	badge_read_PublicKey_from_X509_cert(const char * filename,
		    int * keylen);
extern void *	badge_read_PrivateKey(const char * filename, int * keylen);
extern void *	badge_read_PublicKey(const char * filename, int * keylen);
extern void	badge_free_key(void * key, int isprivate);
extern int	badge_crypt(char * dst, const char * src, int len,
		    char * seedbuf, int seedlen, const badge_entry * e);
extern void	badge_get_random_bytes(char * buf, int count);
extern void	badge_ssl_util_thread_setup(apr_pool_t * p);

extern int	badge_length(const char * badge);
extern const char *
		badge_decode(badge_data * d, const char * bp,
			badge_entry * e, request_rec * r);
extern char *	badge_encode(apr_pool_t * pool,
		    badge_data * b, badge_entry * e);

extern void	badge_parse_query(request_rec * r, const char * varname, ...);
extern const char *
		badge_arg_err(int errflags);
extern void	badge_show(request_rec * r, const badge_data * b,
			const char * badge, const char * key_file,
			const char * verify, badge_timestamp * from,
			badge_timestamp * to, apr_array_header_t * keys,
			int errstatus);

extern const char *
		badge_canonicalize_path(apr_pool_t * p,
			const char * curdir, const char * path);
extern const char *
		badge_match_prefix(const char * uri, const char * prefix);
extern apr_array_header_t *
		badge_unique_key_files(apr_pool_t * pool, badge_conf * conf);
extern int	badge_load_key(badge_entry * e);
extern void	badge_log_perror(const char * file, int line, int level,
			apr_status_t status, apr_pool_t * p,
			const char *fmt, ...);

extern int	badge_factory_handler(request_rec * r);

extern int	badge_decoder_handler(request_rec * r);

extern int	badge_map(request_rec * r);

#endif
