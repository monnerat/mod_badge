/**
***	Badge factory handler: generate badges.
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
badge_get_time_arg(time_t * result, badge_timestamp * ts, int yearerr,
	int montherr, int dayerr, int hourerr, int minerr, int secerr)

{
	apr_time_exp_t exptime;
	apr_time_t aprtime;
	long l;
	char * cp;
	int errflags;

	/**
	***	Convert time components in the given timestamp into a
	***		time_t. Return ored-in error flags.
	**/

	memset((char *) &exptime, 0, sizeof exptime);
	errflags = 0;

	if (ts->year && *ts->year &&
	    (l = strtol(ts->year, &cp, 10)) >= 0 && !*cp) {
		if (l >= 1900)
			l -= 1900;

		exptime.tm_year = l;
		}
	else
		errflags |= yearerr;

	if (ts->month && *ts->month &&
	    (l = strtol(ts->month, &cp, 10)) > 0 && !*cp && l  <= 12)
		exptime.tm_mon = l - 1;
	else
		errflags |= montherr;

	if (ts->day && *ts->day &&
	    (l = strtol(ts->day, &cp, 10)) > 0 && !*cp && l <= 31)
		exptime.tm_mday = l;
	else
		errflags |= dayerr;

	if (ts->hour && *ts->hour &&
	    (l = strtol(ts->hour, &cp, 10)) >= 0 && !*cp && l <= 23)
		exptime.tm_hour = l;
	else
		errflags |= hourerr;

	if (ts->min && *ts->min &&
	    (l = strtol(ts->min, &cp, 10)) >= 0 && !*cp && l <= 59)
		exptime.tm_min = l;
	else
		errflags |= minerr;

	if (ts->sec && *ts->sec &&
	    (l = strtol(ts->sec, &cp, 10)) >= 0 && !*cp && l <= 59)
		exptime.tm_sec = l;
	else
		errflags |= secerr;

	if (errflags)
		return errflags;

	if (apr_time_exp_gmt_get(&aprtime, &exptime) == OK) {
		*result = apr_time_sec(aprtime);

		/* Check for overflow. */

		if (*result == apr_time_sec(aprtime))
			return 0;
		}

	return yearerr | montherr | dayerr;	/* Date problem. */
}


int
badge_factory_handler(request_rec * r)

{
	apr_array_header_t * keys;
	badge_entry * * bep;
	badge_entry * e;
	badge_data b;
	badge_timestamp from;
	badge_timestamp to;
	const char * key_file;
	const char * verify;
	const char * badge;
	int errflags;
	char * myself;
	int i;

	keys = badge_unique_key_files(r->pool, r->server);

	/**
	***	Check parameters: if all are OK, display the result page.
	***	Else show the input form.
	***
	***	Parameters:
	***		from-year	UTC YYYY
	***		from-month	UTC MM
	***		from-day	UTC DD
	***		from-hour	UTC HH
	***		from-min	UTC MM
	***		from-sec	UTC SS
	***		to-year		UTC YYYY
	***		to-month	UTC MM
	***		to-day		UTC DD
	***		to-hour		UTC HH
	***		to-min		UTC MM
	***		to-sec		UTC SS
	***		key-file	Key/certificate file path name.
	***		path-prefix	Path prefix replacement.
	***		username	Auth user name.	optional
	***		password	Password	optional
	***		verify		Password	(should match).
	**/

	badge_parse_query(r,
	    "from-year",	&from.year,	1,
	    "from-month",	&from.month,	1,
	    "from-day",		&from.day,	1,
	    "from-hour",	&from.hour,	1,
	    "from-min",		&from.min,	1,
	    "from-sec",		&from.sec,	1,
	    "to-year",		&to.year,	1,
	    "to-month",		&to.month,	1,
	    "to-day",		&to.day,	1,
	    "to-hour",		&to.hour,	1,
	    "to-min",		&to.min,	1,
	    "to-sec",		&to.sec,	1,
	    "key-file",		&key_file,	1,
	    "path-prefix",	&b.path,	1,
	    "username",		&b.user,	1,
	    "password",		&b.passwd,	0,
	    "verify",		&verify,	0,
	    NULL);

	/**
	***	Check validity of arguments.
	**/

	errflags = 0;
	e = NULL;

	if (r->args) {
		errflags |= badge_get_time_arg(&b.from, &from,
		    BADGE_FROM_YEAR, BADGE_FROM_MONTH, BADGE_FROM_DAY,
		    BADGE_FROM_HOUR, BADGE_FROM_MIN, BADGE_FROM_SEC);
		errflags |= badge_get_time_arg(&b.to, &to,
		    BADGE_TO_YEAR, BADGE_TO_MONTH, BADGE_TO_DAY,
		    BADGE_TO_HOUR, BADGE_TO_MIN, BADGE_TO_SEC);

		if (!errflags && b.from > b.to)
			errflags |= BADGE_FROM_YEAR | BADGE_FROM_MONTH |
			    BADGE_FROM_DAY | BADGE_FROM_HOUR |
			    BADGE_FROM_MIN | BADGE_FROM_SEC |
			    BADGE_TO_YEAR | BADGE_TO_MONTH |
			    BADGE_TO_DAY | BADGE_TO_HOUR |
			    BADGE_TO_MIN | BADGE_TO_SEC;

		if (!b.path || !*b.path)
			errflags |= BADGE_PATH_PREFIX;

		bep = (badge_entry * *) keys->elts;

		if (key_file) {
			errflags |= BADGE_KEY_FILE;

			for (i = 0; i < keys->nelts; i++) {
				if (!strcmp(key_file, (e = *bep)->sslfile)) {
					errflags &= ~BADGE_KEY_FILE;
					break;
					}

				bep++;
				}
			}
		else if (keys->nelts == 1)
			key_file = (e = *bep)->sslfile;
		else
			errflags |= BADGE_KEY_FILE;

		if (!b.user)
			b.user = "";

		if (strchr(b.user, ':'))
			errflags |= BADGE_USERNAME;

		if (!b.passwd)
			b.passwd = "";

		if (!verify)
			verify = "";

		if (strcmp(b.passwd, verify))
			errflags |= BADGE_PASSWORD;

		if (!*b.user && *b.passwd)
			errflags |= BADGE_USERNAME | BADGE_PASSWORD;
		}

	/**
	***	Start the output page.
	**/

	myself = ap_escape_html(r->pool, r->uri);
	ap_set_content_type(r, "text/html");
	ap_rvputs(r, DOCTYPE_HTML_4_0S,
	    "<html>\n",
	    " <head>\n",
	    "  <title>Generate a badge</title>\n",
	    "  <style type=\"text/css\">\n",
	    "   <!--\n",
	    "    .err { background-color: red; }\n",
	    "   -->\n",
	    "  </style>\n",
	    " </head>\n",
	    " <body>\n",
	    "<h1>Generate a badge</h1>\n", NULL);

	/**
	***	If we do have all necessary information, generate a badge.
	**/

	if (!errflags && b.path) {
		b.path = badge_canonicalize_path(r->pool, NULL, b.path) + 1;
		badge = badge_encode(r->pool, &b, e);
		}
	else {
		badge = NULL;
		ap_rvputs(r,
		    "<form method=\"get\" action=\"", myself, "\">\n", NULL);
		}

	/**
	***	Display badge data or input form.
	**/

	badge_show(r, &b, badge, key_file, verify, &from, &to, keys, errflags);

	if (!badge) {
		if (errflags)
			ap_rvputs(r, "<br /><p><span", badge_arg_err(1),
			    ">Please fix the highlighted field(s) and",
			    " retry</span></p>\n", NULL);

		ap_rvputs(r,
		    "<input type=\"submit\" value=\"Generate\" />",
		    "</form>\n", NULL);
		}
	else
		ap_rvputs(r,
		    "<a href=\"", ap_escape_html(r->pool, r->uri),
		    "\">Generate another badge</a>\n", NULL);

	ap_rvputs(r, " </body>\n", "</html>\n", NULL);
	return OK;
}
