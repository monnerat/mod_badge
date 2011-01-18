/**
***	Badge mapper handler: translate URLs containing badges.
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
badge_check_recursion_level(request_rec * r)

{
	const char * cp;
	int recursion;
	int limit;
	module * coremod;
	core_server_config * cconf;

	cp = apr_table_get(r->notes, BADGE_RECURSION);
	recursion = cp? atoi(cp): 0;
	coremod = ap_find_linked_module("core.c");
	limit = AP_DEFAULT_MAX_INTERNAL_REDIRECTS;

	if (coremod) {
		cconf = ap_get_module_config(r->server->module_config,
		    coremod);

		if (cconf->redirect_limit)
			limit = cconf->redirect_limit;
		}

	if (++recursion >= limit)
		return HTTP_INTERNAL_SERVER_ERROR;

	apr_table_set(r->notes, BADGE_RECURSION,
	    apr_psprintf(r->pool, "%d", recursion));

	return OK;
}


int
badge_mapper_handler(request_rec * r)

{
	server_rec * s;
	const char * uri;
	badge_conf * conf;
	badge_entry * e;
	badge_entry * f;
	badge_data bd;
	const char * cp;
	request_rec * subreq;
	ap_conf_vector_t * saveconfig;
	const char * auth;
	int status;

	/**
	***	Badge mapping is computed here and then processed via a
	***		subrequest. The reason is we want access control to
	***		be effective on the original URI.
	**/

	s = r->server;
	conf = ap_get_module_config(s->module_config, &badge_module);
	uri = apr_table_get(r->notes, BADGE_URI_TRANSLATED);

	if (!uri)
		uri = r->uri;

	e = (badge_entry *) conf->badges->elts;

	for (f = e + conf->badges->nelts; e < f; e++) {
		if (!e->key)
			continue;

		cp = badge_match_prefix(uri, e->fake);

		if (!cp)
			continue;

		memset(&bd, 0, sizeof bd);
		cp = badge_decode(&bd, cp, e, r);

		if (!cp)
			continue;

		/* Matching badge found. Check data validty. */

		if ((bd.from && apr_time_from_sec(bd.from) > r->request_time) ||
		    (bd.to && apr_time_from_sec(bd.to) < r->request_time))
			return HTTP_FORBIDDEN;	/* Not yet valid or expired. */

		/**
		***	We can use this badge.
		**/

		if (uri == r->uri)	/* First time through. */
			apr_table_setn(r->notes, BADGE_URI, uri);

		/**
		***	Check recursion level.
		***	This has to be done here, since our subrequests are
		***		not recursive, but our handler invocations are.
		**/

		status = badge_check_recursion_level(r);

		if (status != OK)
			return status;

		/**
		***	Change the authentication parameters accordingly.
		**/

		auth = apr_table_get(r->headers_in, "Authorization");

		if (bd.user && *bd.user) {
			if (auth)
				apr_table_setn(r->notes, BADGE_AUTH, auth);

			apr_table_set(r->headers_in, "Authorization",
			    apr_pstrcat(r->pool, "Basic ",
			    ap_pbase64encode(r->pool, apr_pstrcat(r->pool,
			    bd.user, ":", bd.passwd, NULL)), NULL));
			}

		cp = apr_pstrcat(r->pool, "/", bd.path, cp, NULL);
		apr_table_setn(r->notes, BADGE_URI_TRANSLATED, cp);

		/**
		***	Lookup our new URI: this will process badge
		***		(re-)authentication and allow us to
		***		get effective translated file name,
		***		handler etc.
		**/

		saveconfig = r->per_dir_config;
		r->per_dir_config = NULL;	/* Force reauth. */
		subreq = ap_sub_req_lookup_uri(cp, r, NULL);
		r->per_dir_config = saveconfig;
		status = subreq->status;

		if (auth) {
			apr_table_setn(r->headers_in, "Authorization", auth);

			if (bd.user && *bd.user)
				apr_table_unset(r->notes, BADGE_AUTH);
			}
		else if (bd.user && *bd.user)
			apr_table_unset(r->headers_in, "Authorization");

		if ((cp = apr_table_get(subreq->headers_out, "Location")))
			apr_table_set(r->headers_out, "Location", cp);

		if (status < 300) {
			r->filename = subreq->filename;
			r->finfo = subreq->finfo;
			r->used_path_info = subreq->used_path_info;
			r->path_info = subreq->path_info;
			r->handler = subreq->handler;
			r->user = subreq->user;
			r->ap_auth_type = subreq->ap_auth_type;
			ap_set_content_type(r, subreq->content_type);
			status = ap_run_quick_handler(r, 0);

			if (status == DECLINED)
				status = ap_invoke_handler(r);
			}

		ap_destroy_sub_req(subreq);
		return status;
		}

	/**
	***	No badge mapping possible: process via another handler.
	**/

	return DECLINED;
}
