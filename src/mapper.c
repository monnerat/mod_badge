/**
***	Badge mapper: translate URLs containing badges.
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


static const char *
badge_find(request_rec * r, badge_data * b, char * uri, badge_conf * conf)

{
	badge_entry * e;
	badge_entry * f;
	const char * cp;

	/**
	***	Find the badge in URI according to configuration and
	***		decode it.
	***	Return pointer to URL after the badge if found, else NULL.
	**/

	e = (badge_entry *) conf->badges->elts;

	for (f = e + conf->badges->nelts; e < f; e++) {
		if (!e->key)
			continue;

		cp = badge_match_prefix(uri, e->fake);

		if (!cp)
			continue;

		memset(b, 0, sizeof *b);
		cp = badge_decode(b, cp, e, r);

		if (!cp)
			continue;

		/* Matching badge found. Check data validty. */

		if (b->from && apr_time_from_sec(b->from) > r->request_time)
			continue;

		if (!b->to || apr_time_from_sec(b->to) >= r->request_time)
			return cp;		/* Found. */
		}

	return NULL;				/* No usable badge found. */
}


int
badge_map(request_rec * r)

{
	badge_conf * conf;
	badge_data bd;
	const char * cp;
	const char * auth;
	int status;
	int maxloop;
	module * coremod;
	core_server_config * cconf;

	/**
	***	Map URI if it contains badges.
	***	Return status (OK if changes performed, DECLINED if none).
	**/

	conf = ap_get_module_config(r->per_dir_config, &badge_module);

	if (!(cp = badge_find(r, &bd, r->uri, conf)))
		return DECLINED;		/* No badge in this URI. */

	auth = apr_table_get(r->headers_in, "Authorization");

	/**
	***	Limit the badge count in an URI to the maximum redirection
	***		count.
	**/

	coremod = ap_find_linked_module("core.c");
	maxloop = AP_DEFAULT_MAX_INTERNAL_REDIRECTS;

	if (coremod) {
		cconf = ap_get_module_config(r->server->module_config,
		    coremod);

		if (cconf->redirect_limit)
			maxloop = cconf->redirect_limit;
		}

	do {
		r->uri = apr_pstrcat(r->pool, "/", bd.path, cp, NULL);

		if (bd.user && *bd.user)
			if (!auth || conf->keepauth <= 0) {
				/**
				***	Build and set faked authorization.
				**/

				auth = apr_pstrcat(r->pool, bd.user, ":",
				    bd.passwd, NULL);
				auth = ap_pbase64encode(r->pool, auth);
				auth = apr_pstrcat(r->pool, "Basic ",
				    auth, NULL);
				apr_table_set(r->headers_in, "Authorization",
					auth);
				}

		/**
		***	Give a chance to find badges specific to
		***		translated URI.
		**/

		status = ap_location_walk(r);
	} while (status == OK && --maxloop &&
	    (cp = badge_find(r, &bd, r->uri, conf)));

	return status;
}
