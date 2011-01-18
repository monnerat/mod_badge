/**
***	mod_badge: support for html and form request handling.
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

#ifdef APR_HAVE_STDARG_H
#include <stdarg.h>
#endif



static char
badge_unescape_query_char(const char * * pp)

{
	const char * p;
	int c;
	int d;

	/**
	***	Get a possibly escaped character from pointer at `pp' and
	***		unescape it.
	**/

	p = *pp;
	c = *p++;

	switch (c) {

	case '\0':
		p--;
		break;

	case '+':
		c = ' ';
		break;

	case '%':
		if (!apr_isxdigit(p[0]) || !apr_isxdigit(p[1]))
			break;

		d = *p++;
		c = *p++;

		if (d >= '0' && d <= '9')
			d -= '0';
		else if (d >= 'a' && d <= 'f')
			d -= 'a' - 10;
		else
			d -= 'A' - 10;

		if (c >= '0' && c <= '9')
			c -= '0';
		else if (c >= 'a' && c <= 'f')
			c -= 'a' - 10;
		else
			c -= 'A' - 10;

		c |= d << 4;
		break;
		}

	*pp = p;
	return c;
}


/* VARARGS2 */
void
badge_parse_query(request_rec * r, const char * varname, ...)

{
	va_list va;
	const char * q;
	char * p;
	char * n;
	char * v;
	char c;
	const char * vn;
	const char * * vv;
	int trim;
	int i;

	/**
	***	Parse a form-url-encoding formatted string into variables
	***		listed in parameters.
	***	Each variable is given as:
	***		const char *	name	The variable name
	***		char * *	value	Where to store its value
	***		int		strip	Set to trim value
	***	The variable list is terminated by a NULL pointer.
	**/

	va_start(va, varname);

	/**
	***	Clear variables.
	**/

	for (vn = varname; vn; vn = va_arg(va, const char *)) {
		vv = va_arg(va, const char * *);
		trim = va_arg(va, int);

		if (vv)
			*vv = NULL;
		}

	va_end(va);
	q = r->args;

	if (!q || !*q)
		return;

	p = apr_pcalloc(r->pool, strlen(q) + 1);
	c = *q;					/* Lookahead character. */

	while (c) {
		/**
		***	Get a 'name=value' pair from query.
		**/

		for (n = p; c && c != '=' && c != '&'; c = *q)
			*p++ = badge_unescape_query_char(&q);

		*p++ = '\0';

		if (c == '=') {
			c = *++q;

			for (v = p; c && c != '&'; c = *q)
				*p++ = badge_unescape_query_char(&q);

			*p++ = '\0';
			}
		else
			v = p - 1;

		/**
		***	Save value if name provided as function argument.
		**/

		va_start(va, varname);

		for (vn = varname; vn; vn = va_arg(va, const char *)) {
			vv = va_arg(va, const char * *);
			trim = va_arg(va, int);

			if (!vv || strcmp(vn, n))
				continue;

			if (trim) {
				while (*v == ' ' || *v == '\t')
					v++;

				for (i = p - v; i--;)
					if (v[i] != ' ' && v[i] != '\t')
						break;

				v[++i] = '\0';
				}

			*vv = v;
			}

		va_end(va);

		if (c)
			c = *++q;
		}
}


const char *
badge_arg_err(int errflags)

{
	/**
	***	Return error class if flag is set.
	**/

	return errflags? " class=\"err\"": "";
}


static void
badge_emit_text(request_rec * r, const char * label, const char * value,
	int rdonly, const char * name, int pwflg, int errflg)

{
	/**
	***	Generate the given text value as an html table row, either
	***		as normal text or as an input field according to
	***		the `rdonly' flag.
	**/

	if (!value)
		value = "";
	else
		value = ap_escape_html(r->pool, value);

	ap_rvputs(r, "<tr><td>", label, "</td><td", badge_arg_err(errflg),
	    ">", NULL);

	if (rdonly)
		ap_rvputs(r, value, "</td></tr>\n", NULL);
	else
		ap_rvputs(r, "<input type=\"", pwflg? "password": "text",
		    "\" name=\"", name, "\" value=\"", value,
		    "\" /></td></tr>\n", NULL);
}


static void
badge_emit_range_select(request_rec * r, const char * label, const char * name1,
	const char * name2, int low, int high, const char * curval, int errflag)

{
	int selval;
	char buf[10];

	/**
	***	Generate an html select for a given integer range.
	**/

	selval = curval? atoi(curval): 0;
	ap_rvputs(r, "&nbsp;", label, "<select name=\"", name1, "-", name2,
	    "\"", badge_arg_err(errflag), ">\n", NULL);

	for (; low <= high; low++) {
		snprintf(buf, sizeof buf, "%d", low);
		ap_rvputs(r, " <option", selval == low? " selected=\"yes\"": "",
		    " value=\"", buf, "\">", buf, "</option>\n", NULL);
		}

	ap_rvputs(r, "</select>", NULL);
}


static void
badge_emit_timestamp(request_rec * r, const char * fromto, time_t value,
	int rdonly, badge_timestamp * ts, int errflags, int yearerr,
	int montherr, int dayerr, int hourerr, int minerr, int secerr)

{
	apr_time_exp_t exptime;
	apr_time_t aprtime;
	apr_size_t len;
	char buf[100];

	/**
	***	Emit a timestamp in an html table row, either as normal text
	***		from `value' or as input fields with values from `*ts'
	***		according to the `rdonly' flag.
	**/

	ap_rvputs(r, "<tr><td>Valid ", fromto, "</td><td>", NULL);

	if (rdonly) {
		apr_time_ansi_put(&aprtime, value);
		apr_time_exp_tz(&exptime, aprtime, 0);
		apr_strftime(buf, &len, sizeof buf - 1, "%c", &exptime);
		buf[len] = '\0';
		ap_rvputs(r, ap_escape_html(r->pool, buf), NULL);
		}
	else {
		ap_rvputs(r, "Y<input type=\"text\" name=\"", fromto,
		    "-year\" value=\"",
		    ts->year? ap_escape_html(r->pool, ts->year): "",
		    "\"", badge_arg_err(errflags & yearerr), " />", NULL);
		badge_emit_range_select(r, "M", fromto,
		    "month", 1, 12, ts->month, errflags & montherr);
		badge_emit_range_select(r, "D", fromto,
		    "day", 1, 31, ts->day, errflags & dayerr);
		badge_emit_range_select(r, "H", fromto,
		    "hour", 0, 23, ts->hour, errflags & hourerr);
		badge_emit_range_select(r, "M", fromto,
		    "min", 0, 59, ts->min, errflags & minerr);
		badge_emit_range_select(r, "S", fromto,
		    "sec", 0, 59, ts->sec, errflags & secerr);
		}

	ap_rvputs(r, "</td></tr>\n", NULL);
}


void
badge_show(request_rec * r, const badge_data * b, const char * badge,
	const char * key_file, const char * verify, badge_timestamp * from,
	badge_timestamp * to, apr_array_header_t * keys, int errstatus)

{
	int isform;
	badge_entry * * bep;
	const char * cp;
	int i;

	/**
	***	Display badge data or input form.
	**/

	isform = !badge;
	ap_rvputs(r, "<table border=\"0\"><tbody>\n", NULL);

	/**
	***	Key file path entry.
	**/

	ap_rvputs(r, "<tr><td>Key file path</td>\n",
	    "<td", badge_arg_err(errstatus & BADGE_KEY_FILE), ">", NULL);

	if (!isform)
		ap_rvputs(r, ap_escape_html(r->pool, key_file), NULL);
	else {
		bep = (badge_entry * *) keys->elts;

		if (!key_file)
			key_file = (*bep)->sslfile;

		if (keys->nelts == 1) {
			cp = ap_escape_html(r->pool, key_file);
			ap_rvputs(r, "<input type=\"hidden\" name=\"key-file\"",
			    " value=\"", cp, "\" />cp", NULL);
			}
		else {
			ap_rvputs(r, "<select name=\"key-file\">\n", NULL);

			for (i = 0; i < keys->nelts; i++) {
				ap_rvputs(r, " <option",
				    strcmp(key_file, (*bep)->sslfile)? "":
				    " selected=\"yes\"", ">",
				    ap_escape_html(r->pool, (*bep)->sslfile),
				    "</option>\n", NULL);
				bep++;
				}

			ap_rvputs(r, "</select>", NULL);
			}
		}

	ap_rvputs(r, "</td></tr>\n", NULL);

	/**
	***	Replacement path entry.
	**/

	badge_emit_text(r, "Replacement path prefix", b->path, !isform,
	    "path-prefix", 0, errstatus & BADGE_PATH_PREFIX);

	/**
	***	"Valid from" timestamp entry.
	**/

	badge_emit_timestamp(r, "from", b->from, !isform, from, errstatus,
	    BADGE_FROM_YEAR, BADGE_FROM_MONTH, BADGE_FROM_DAY,
	    BADGE_FROM_HOUR, BADGE_FROM_MIN, BADGE_FROM_SEC);

	/**
	***	"Valid to" timestamp entry.
	**/

	badge_emit_timestamp(r, "to", b->to, !isform, to, errstatus,
	    BADGE_TO_YEAR, BADGE_TO_MONTH, BADGE_TO_DAY,
	    BADGE_TO_HOUR, BADGE_TO_MIN, BADGE_TO_SEC);

	/**
	***	User name entry.
	**/

	if (isform || (b->user && *b->user))
		badge_emit_text(r, "Authentication user", b->user, !isform,
		    "username", 0, errstatus & BADGE_USERNAME);

	/**
	***	Password entry.
	**/

	if (isform || (b->user && *b->user))
		badge_emit_text(r, "Password",
		    !badge? b->passwd: b->passwd && *b->passwd? "set": "unset",
		    !isform, "password", 1, errstatus & BADGE_PASSWORD);

	/**
	***	Password verify entry.
	**/

	if (isform)
		badge_emit_text(r, "Verify password", verify, 0,
		    "verify", 1, errstatus & BADGE_PASSWORD);

	/**
	***	If a badge has been generated, show it.
	**/

	if (badge) {
		ap_rvputs(r, "<tr><td colspan=\"2\">&nbsp;</td></tr>\n", NULL);
		badge_emit_text(r, "Badge", badge, 1, "", 0, 0);
		}

	ap_rvputs(r, "</tbody></table>\n", NULL);
}
