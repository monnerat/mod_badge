/**
***	Badge formatter: clear data <--> badge conversions.
***
***	Copyright 2011 DATASPHERE S.A.
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

#include "mod_badge.h"


static int
badge_number_length(apr_uint32_t n)

{
	int len;

	/**
	***	Numbers are stored 7-bit/byte, MSB first, with MSB of all
	***		but last byte set.
	**/

	for (len = 1; n >>= 7; len++)
		;

	return len;
}


static int
badge_string_length(const char * s)

{
	int len;

	/**
	***	Strings are stored prefixed by their encoded length.
	**/

	len = strlen(s);
	return len + badge_number_length(len);
}


static char *
badge_encode_number_recursive(char * p, apr_uint32_t n)

{
	char c;

	c = n & 0x7F;
	n >>= 7;

	if (n)
		p = badge_encode_number_recursive(p, n);

	*p++ = 0x80 | c;
	return p;
}


static char *
badge_encode_number(char * p, apr_uint32_t n)

{
	/**
	***	Encode a number in our external format.
	**/

	if (n & ~0x7F)
		p = badge_encode_number_recursive(p, n >> 7);

	*p++ = n & 0x7F;
	return p;
}


static char *
badge_encode_string(char * p, const char * s)

{
	int len;

	/**
	***	Encode a string in our external format.
	**/

	len = strlen(s);
	p = badge_encode_number(p, len);

	if (len)
		memcpy(p, s, len);

	return p + len;
}


static apr_uint32_t
badge_decode_number(const char * * datap, const char * edata, int * overflow)

{
	const char * cp;
	apr_uint32_t n;
	int b;

	/**
	***	Decode a number from external format.
	***	Set the `overflow` flag if the num is too big or if the
	***		data stream is too short.
	***	Data pointer is updated accordingly.
	**/

	cp = *datap;
	n = 0;

	do {
		if (cp >= edata || (n & ~0x01FFFFFF)) {
			*overflow = 1;
			break;
			}

		b = *cp++;

		if (!n && b == 0x80) {
			*overflow = 1;	/* Invalid number format. */
			break;
			}

		n = (n << 7) | (b & 0x7F);
	} while (b & 0x80);

	*datap = cp;
	return n;
}


static apr_size_t
badge_decode_string(const char * * datap, const char * edata,
					const char * * valp, int * overflow)

{
	apr_size_t len;
	const char * cp;

	/**
	***	Decode a string from external format.
	***	Set the `overflow` flag if the num is too big or if the
	***		data stream is too short.
	***	Data pointer is updated accordingly.
	**/

	len = badge_decode_number(datap, edata, overflow);
	cp = *datap;
	*valp = cp;

	if (cp + len > edata)
		*overflow = 1;

	if (*overflow)
		return 0;

	*datap = cp + len;
	return len;
}


static int
badge_decode_0(badge_data * d,
		const char * data, const char * enddata, request_rec * r)

{
	const char * cp;
	int overflow;
	int pathlen;
	int userlen;
	int passwdlen;
	apr_uint32_t crc32;

	/**
	***	Try decoding a badge according to version 0 of the
	***		external format.
	**/

	cp = data;
	overflow = 0;
	d->version = badge_decode_number(&cp, enddata, &overflow);

	if (overflow || d->version != 0)
		return DECLINED;	/* Data not in format version 0. */

	d->from = badge_decode_number(&cp, enddata, &overflow);
	d->to = badge_decode_number(&cp, enddata, &overflow);
	pathlen = badge_decode_string(&cp, enddata, &d->path, &overflow);
	userlen = badge_decode_string(&cp, enddata, &d->user, &overflow);
	passwdlen = badge_decode_string(&cp, enddata, &d->passwd, &overflow);
	crc32 = apr_memcache_hash_crc32(NULL, data, cp - data);

	if (crc32 != badge_decode_number(&cp, enddata + 1, &overflow))
		return DECLINED;	/* Data not in format version 0. */

	if (overflow || cp != enddata)
		return DECLINED;	/* Data not in format version 0. */

	/**
	***	Strip leading and trailing slashes in path.
	**/

	while (pathlen && d->path[pathlen - 1] == '/')
		pathlen--;

	while (pathlen && d->path[0] == '/') {
		d->path++;
		pathlen--;
		}

	/**
	***	Data OK. Move strings to dynamic storage.
	**/

	d->path = apr_pstrndup(r->pool, d->path, pathlen);
	d->user = apr_pstrndup(r->pool, d->user, userlen);
	d->passwd = apr_pstrndup(r->pool, d->passwd, passwdlen);
	d->to += d->from;			/* Duration --> timestamp. */
	return OK;
}


int
badge_length(const char * badge)

{
	const char * cp;

	/**
	***	Return badge length by checking legality of characters.
	**/

	for (cp = badge; apr_isalnum(*cp) || *cp == '-' || *cp == '_'; cp++)
		;

	return cp - badge;
}


const char *
badge_decode(badge_data * d, const char * bp, badge_entry * e, request_rec * r)

{
	const char * cp;
	const char * ep;
	char * temp1;
	char * temp2;
	char * seedbuf;
	int len;
	int i;
	int overflow;

	/**
	***	Try decoding badge at `bp' using the given entry key.
	***	Return a pointer to the first byte after the badge
	***		string (and trailing slasshes) if OK, else NULL.
	**/

	len = badge_length(bp);
	cp = bp + len;

	if (*cp && *cp != '/')
		return NULL;			/* Not a valid badge. */

	/**
	***	Allocate working space.
	**/

	temp1 = apr_pcalloc(r->pool, len + 2);
	temp2 = apr_pcalloc(r->pool, 1 + ((len * 3) >> 2));

	/**
	***	Convert badge to base64 data.
	**/

	for (i = 0; i < len; i++)
		switch (bp[i]) {

		case '-':
			temp1[i] = '+';
			break;

		case '_':
			temp1[i] = '/';
			break;

		default:
			temp1[i] = bp[i];
			break;
			}

	if (len & 0x03)
		temp1[len++] = '=';

	temp1[len] = '\0';

	/**
	***	Decode base64 data.
	**/

	len = apr_base64_decode(temp2, temp1);

	/**
	***	Skip redundant slashes after badge in URI.
	**/

	if (*cp)
		while (cp[1] == '/')
			cp++;

	bp = cp;

	/**
	***	Try decryption according to format version 0 seed length.
	**/

	seedbuf = apr_pcalloc(r->pool, e->keylen);

	if (len >= SEED_LEN_0) {
		i = badge_crypt(temp1, temp2, len, seedbuf, SEED_LEN_0, e);
		temp1[i] = 0;			/* Append a sentinel. */
		cp = temp1;
		ep = temp1 + i;
		overflow = 0;
		d->version = badge_decode_number(&cp, ep, &overflow);

		if (!overflow)
			switch (d->version) {

			case 0:		/* Try data format version 0. */
				if (badge_decode_0(d, temp1, ep, r) == OK)
					return bp;	/* Badge OK. */
				}
		}

	return NULL;
}


char *
badge_encode(apr_pool_t * pool, badge_data * b, badge_entry * e)

{
	int len;
	int seedlen;
	apr_uint32_t duration;
	char * databuf;
	char * buf;
	char * p;

	/**
	***	Create a badge with the given badge data.
	***	Return a pointer to the null-terminated badge string.
	**/

	b->version = 0;			/* Data format version. */
	seedlen = SEED_LEN_0;
	duration = b->to - b->from;

	/**
	***	Compute data length and allocate a buffer for it.
	**/

	len = seedlen + badge_number_length(b->version) +
	    badge_number_length(b->from) +
	    badge_number_length(duration) +
	    badge_string_length(b->path) +
	    badge_string_length(b->user) +
	    badge_string_length(b->passwd) +
	    badge_number_length(~0);	/* Room for CRC-32. */
	databuf = apr_pcalloc(pool, len);

	/**
	***	Fill the buffer with data.
	**/

	badge_get_random_bytes(databuf, seedlen);
	buf = databuf + seedlen;
	p = badge_encode_number(buf, b->version);
	p = badge_encode_number(p, b->from);
	p = badge_encode_number(p, duration);
	p = badge_encode_string(p, b->path);
	p = badge_encode_string(p, b->user);
	p = badge_encode_string(p, b->passwd);
	p = badge_encode_number(p, apr_memcache_hash_crc32(NULL, buf, p - buf));

	/**
	***	Allocate another buffer: it will be used for temporary
	***		encryption data (keylen bytes), and later for
	***		our final modified base64 result.
	**/

	len = 1 + apr_base64_encode_len(p - databuf);

	if (len < e->keylen)
		len = e->keylen;

	buf = apr_pcalloc(pool, len);

	/**
	***	Encrypt data.
	**/

	badge_crypt(databuf + seedlen, databuf, p - databuf, buf, seedlen, e);

	/**
	***	Convert to base64.
	**/

	len = apr_base64_encode(buf, databuf, p - databuf);
	buf[len] = '\0';

	/**
	***	Map non-URI characters. Return when done.
	**/

	for (p = buf;; p++)
		switch (*p) {

		case '+':
			*p = '-';
			break;

		case '/':
			*p = '_';
			break;

		case '=':
			*p = '\0';	/* Strip trailing equal signs. */

		case '\0':
			return buf;
			}
}
