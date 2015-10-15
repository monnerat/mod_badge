/**
***	mod_badge: SSL support.
***	Heavily copied from mod_ssl.
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

#include "openssl/bio.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "openssl/rsa.h"
#include "openssl/err.h"
#include "openssl/rand.h"

#include "mod_badge.h"


#define badge_read_ssl(func1, func2)					\
	for (;;) {	/* Need a breakable block. */			\
		BIO * bioS;						\
		BIO * bioF;						\
									\
		/* 1. Try PEM (= DER+Base64+headers). */		\
									\
		bioS = BIO_new_file(filename, "r");			\
									\
		if (!bioS) {						\
			rc = NULL;					\
			break;						\
			}						\
									\
		rc = func1(bioS, NULL, NULL, NULL);			\
		BIO_free(bioS);						\
									\
		if (rc)							\
			break;						\
									\
		/* 2. Try DER+Base64. */				\
									\
		bioS = BIO_new_file(filename, "r");			\
									\
		if (!bioS)						\
			break;						\
									\
		bioF = BIO_new(BIO_f_base64());				\
									\
		if (!bioF) {						\
			BIO_free(bioS);					\
			break;						\
			}						\
									\
		bioS = BIO_push(bioF, bioS);				\
		rc = func2(bioS, NULL);					\
		BIO_free_all(bioS);					\
									\
		if (rc)							\
			break;						\
									\
		/* 3. Try plain DER. */					\
									\
		bioS = BIO_new_file(filename, "r");			\
									\
		if (!bioS)						\
			break;						\
									\
		rc = func2(bioS, NULL);					\
		BIO_free(bioS);						\
		break;							\
	}

void *
badge_read_PublicKey_from_X509_cert(const char * filename, int * keylen)

{
	X509 * rc;
	EVP_PKEY * key;

	badge_read_ssl(PEM_read_bio_X509, d2i_X509_bio);

	if (!rc)
		return NULL;

	key = X509_get_pubkey(rc);
	X509_free(rc);

	if (key)
		*keylen = EVP_PKEY_size(key);

	return key;
}


void *
badge_read_PrivateKey(const char * filename, int * keylen)

{
	EVP_PKEY * rc;

	badge_read_ssl(PEM_read_bio_PrivateKey, d2i_PrivateKey_bio);

	if (rc)
		*keylen = EVP_PKEY_size(rc);

	return rc;
}


void *
badge_read_PublicKey(const char * filename, int * keylen)

{
	EVP_PKEY * rc;

	badge_read_ssl(PEM_read_bio_PUBKEY, d2i_PUBKEY_bio);

	if (rc)
		*keylen = EVP_PKEY_size(rc);

	return rc;
}


void
badge_free_key(void * key, int isprivate)

{
	EVP_PKEY_free((EVP_PKEY *) key);
}


int
badge_crypt(char * dst, const char * src, int len,
			char * seedbuf, int seedlen, const badge_entry * e)

{
	const char * esrc;
	int i;
	EVP_PKEY * key;

	if (len <= seedlen)
		return 0;

	/**
 	***	Always use type 1 padding since we do not want randomization.
	**/

	RSA_padding_add_PKCS1_type_1((unsigned char *) seedbuf, e->keylen,
	    (const unsigned char *) src, seedlen);
	src += seedlen;
	len -= seedlen;
	esrc = src + len;
	i = e->keylen;
	key = (EVP_PKEY *) e->key;

	while (src < esrc) {
		if (i >= e->keylen) {
			if (e->isprivate)
				i = RSA_private_encrypt(e->keylen,
				    (unsigned char *) seedbuf,
				    (unsigned char *) seedbuf,
				    key->pkey.rsa, RSA_NO_PADDING);
			else
				i = RSA_public_encrypt(e->keylen,
				    (unsigned char *) seedbuf,
				    (unsigned char *) seedbuf,
				    key->pkey.rsa, RSA_NO_PADDING);

			i = 0;
			}

		*dst++ = *src++ ^ seedbuf[i++];
		}

	return len;
}


void
badge_get_random_bytes(char * buf, int count)

{
	RAND_pseudo_bytes((unsigned char *) buf, count);
}



#if APR_HAS_THREADS

/**
***	Thread-safeness in OpenSSL. Normally handled by mod_ssl in a way
***		that satisfies this module's requirements. But we might
***		consider the case where mod_ssl is not loaded. For this
***		particular case, handle thread-safeness here.
**/


struct CRYPTO_dynlock_value {		/* Dynamic lock structure */
	apr_pool_t *		pool;
	const char *		file; 
	int			line;
	apr_thread_mutex_t *	mutex;
};

static apr_thread_mutex_t * *	lock_cs;
static int			lock_num_locks;

/**
***	Global reference to the pool passed into ssl_util_thread_setup().
**/

static apr_pool_t *		dynlockpool = NULL;


/**
***	OpenSSL static lock/unlock callback,
**/

#ifndef HAVE_SSLC
static void
ssl_util_thr_lock(int mode, int type, const char * file, int line)
#elif SSLC_VERSION_NUMBER >= 0x2000
static int
ssl_util_thr_lock(int mode, int type, char * file, int line)
#else
static void
ssl_util_thr_lock(int mode, int type, char * file, int line)
#endif

{
	if (type < lock_num_locks) {
		if (mode & CRYPTO_LOCK)
			apr_thread_mutex_lock(lock_cs[type]);
		else
			apr_thread_mutex_unlock(lock_cs[type]);

#ifdef HAVE_SSLC
#if SSLC_VERSION_NUMBER >= 0x2000
		return 1;
		}
	else {
		return -1;
#endif
#endif
		}
}


/**
***	Dynamic lock creation callback.
**/

static struct CRYPTO_dynlock_value *
ssl_dyn_create_function(const char * file, int line)

{
	struct CRYPTO_dynlock_value * value;
	apr_pool_t * p;
	apr_status_t rv;

	/** 
	***	We need a pool to allocate our mutex. Since we can't clear
	***		allocated memory from a pool, create a subpool that
	***		we can blow away in the destruction callback. 
	**/

	rv = apr_pool_create(&p, dynlockpool);

	if (rv != APR_SUCCESS) {
		badge_log_perror(file, line, APLOG_ERR, rv, dynlockpool, 
		    "Failed to create subpool for dynamic lock");
		return NULL;
		}

	badge_log_perror(file, line, APLOG_DEBUG, 0, p,
	    "Creating dynamic lock");
	value = (struct CRYPTO_dynlock_value *) apr_palloc(p, sizeof *value);

	if (!value) {
		badge_log_perror(file, line, APLOG_ERR, 0, p, 
		    "Failed to allocate dynamic lock structure");
		apr_pool_destroy(p);
		return NULL;
		}

	value->pool = p;

	/**
	***	Keep our own copy of the place from which we were created,
	***		using our own pool.
	**/

	value->file = apr_pstrdup(p, file);
	value->line = line;
	rv = apr_thread_mutex_create(&value->mutex,
	    APR_THREAD_MUTEX_DEFAULT, p);

	if (rv != APR_SUCCESS) {
		badge_log_perror(file, line, APLOG_ERR, rv, p, 
		    "Failed to create thread mutex for dynamic lock");
		apr_pool_destroy(p);
		return NULL;
		}

	return value;
}


/**
***	Dynamic locking and unlocking function.
**/

static void
ssl_dyn_lock_function(int mode, struct CRYPTO_dynlock_value * l,
						const char * file, int line)

{
	apr_status_t rv;

	if (mode & CRYPTO_LOCK) {
		badge_log_perror(file, line, APLOG_DEBUG, 0, l->pool, 
		    "Acquiring mutex %s:%d", l->file, l->line);
		rv = apr_thread_mutex_lock(l->mutex);
		badge_log_perror(file, line, APLOG_DEBUG, rv, l->pool, 
		    "Mutex %s:%d acquired!", l->file, l->line);
		}
	else {
		badge_log_perror(file, line, APLOG_DEBUG, 0, l->pool, 
		    "Releasing mutex %s:%d", l->file, l->line);
		rv = apr_thread_mutex_unlock(l->mutex);
		badge_log_perror(file, line, APLOG_DEBUG, rv, l->pool, 
		    "Mutex %s:%d released!", l->file, l->line);
		}
}


/**
***	Dynamic lock destruction callback.
**/

static void ssl_dyn_destroy_function(struct CRYPTO_dynlock_value * l, 
						const char * file, int line)

{
	apr_status_t rv;

	badge_log_perror(file, line, APLOG_DEBUG, 0, l->pool, 
	    "Destroying dynamic lock %s:%d", l->file, l->line);
	rv = apr_thread_mutex_destroy(l->mutex);

	if (rv != APR_SUCCESS)
		badge_log_perror(file, line, APLOG_ERR, rv, l->pool, 
		    "Failed to destroy mutex for dynamic lock %s:%d", 
		    l->file, l->line);

	/**
	***	Trust that whomever owned the CRYPTO_dynlock_value we were
	***		passed has no future use for it...
	**/

	apr_pool_destroy(l->pool);
}


static unsigned long
ssl_util_thr_id(void)

{
	/**
	***	OpenSSL needs this to return an unsigned long. On OS/390,
	***		the pthread id is a structure twice that big. Use the
	***		TCB pointer instead as a unique unsigned long.
	**/

#ifdef __MVS__
	struct PSA {
		char		unmapped[540];
		unsigned long	PSATOLD;
	} * psaptr = 0;

	return psaptr->PSATOLD;
#else
	return (unsigned long) apr_os_thread_current();
#endif
}


static apr_status_t
ssl_util_thread_cleanup(void * data)

{
	CRYPTO_set_locking_callback(NULL);
	CRYPTO_set_id_callback(NULL);

	CRYPTO_set_dynlock_create_callback(NULL);
	CRYPTO_set_dynlock_lock_callback(NULL);
	CRYPTO_set_dynlock_destroy_callback(NULL);

	dynlockpool = NULL;

	/**
	***	Let the registered mutex cleanups do their own thing.
	**/

	return APR_SUCCESS;
}

#endif


void
badge_ssl_util_thread_setup(apr_pool_t * p)

{
#if APR_HAS_THREADS
	int i;

	/**
	***	If mod_ssl is loaded, let it do the job.
	**/

	if (ap_find_linked_module("mod_ssl.c"))
		return;

	lock_num_locks = CRYPTO_num_locks();
	lock_cs = apr_palloc(p, lock_num_locks * sizeof *lock_cs);

	for (i = 0; i < lock_num_locks; i++)
		apr_thread_mutex_create(lock_cs + i,
		    APR_THREAD_MUTEX_DEFAULT, p);

	CRYPTO_set_id_callback(ssl_util_thr_id);
	CRYPTO_set_locking_callback(ssl_util_thr_lock);

	/**
	***	Set up dynamic locking scaffolding for OpenSSL to use at its
	***		convenience. 
	**/

	dynlockpool = p;
	CRYPTO_set_dynlock_create_callback(ssl_dyn_create_function);
	CRYPTO_set_dynlock_lock_callback(ssl_dyn_lock_function);
	CRYPTO_set_dynlock_destroy_callback(ssl_dyn_destroy_function);

	apr_pool_cleanup_register(p, NULL,
	    ssl_util_thread_cleanup, apr_pool_cleanup_null);
#endif
}
