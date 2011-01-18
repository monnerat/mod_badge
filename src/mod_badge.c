/**
***	mod_badge: Apache module interface.
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
add_badge(cmd_parms * cmd, void * dconfig,
					const char * fake, const char * sslfile)

{
	server_rec * s;
	badge_conf * conf;
	badge_entry * new;

	s = cmd->server;
	conf = ap_get_module_config(s->module_config, &badge_module);
	new = apr_array_push(conf->badges);
	new->fake = badge_canonicalize_path(cmd->pool, "/", fake);
	new->sslfile = ap_server_root_relative(cmd->pool, sslfile);
	new->key = NULL;
	badge_load_key(new, s);
	return NULL;
}


static const command_rec	badge_cmds[] = {
	AP_INIT_TAKE2("BadgeMap", add_badge, NULL, RSRC_CONF,
	    "a fake URL prefix and a certificate or key filename"),
	{	NULL	}
};


static void *
create_badge_config(apr_pool_t * p, server_rec * s)

{
	badge_conf * a;

	a = (badge_conf *) apr_pcalloc(p, sizeof *a);
	a->badges = apr_array_make(p, 20, sizeof(badge_entry));
	return a;
}


static void *
merge_badge_config(apr_pool_t * p, void * basev, void * overridesv)

{
	badge_conf * a;
	badge_conf * base;
	badge_conf * overrides;

	a = (badge_conf *) apr_pcalloc(p, sizeof *a);
	base = (badge_conf *) basev;
	overrides = (badge_conf *) overridesv;
	a->badges = apr_array_append(p, overrides->badges, base->badges);
	return a;
}


static int
badge_post_config(apr_pool_t * pconf, apr_pool_t * plog, apr_pool_t * ptemp,
							server_rec * r)

{
	/**
	***	Initialize for thread-safetyness. This can be done here
	***		since no new thread has been started prior to
	***		calling this procedure.
	**/

	badge_ssl_util_thread_setup(pconf);
	return OK;
}


static int
badge_fixups(request_rec * r)

{
	request_rec * pr;
	const char * uri;
	const char * auth;

	/**
	***	Restore the original URI before all other fixups to
	***		all proper generation of "Location" header if some.
	**/

	pr = r->main;

	if (!pr)
		return DECLINED;		/* Not in a subrequest. */

	uri = apr_table_get(pr->notes, BADGE_URI);

	if (!uri)
		return DECLINED;		/* Not in badge subrequest. */

	r->uri = (char *) uri;
	auth = apr_table_get(pr->notes, BADGE_AUTH);

	if (auth)
		apr_table_setn(r->headers_in, "Authorization", auth);

	return OK;
}


static int
badge_handler(request_rec * r)

{
	if (!strcmp(r->handler, "badge-factory"))
		return badge_factory_handler(r);

	if (!strcmp(r->handler, "badge-decoder"))
		return badge_decoder_handler(r);

	return badge_mapper_handler(r);
}


static void
badge_register_hooks(apr_pool_t * p)

{
	static const char * const fixups_successors[] = {
		"mod_rewrite.c",
		"mod_proxy.c",
		NULL
		};

	ap_hook_post_config(badge_post_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_fixups(badge_fixups, NULL, fixups_successors,
	    APR_HOOK_FIRST);
	ap_hook_handler(badge_handler, NULL, NULL, APR_HOOK_FIRST);
}


module AP_MODULE_DECLARE_DATA	badge_module = {
	STANDARD20_MODULE_STUFF,
	NULL,				/* Create directory configuration. */
	NULL,				/* Merge directory configuration. */
	create_badge_config,		/* Create server configuration. */
	merge_badge_config,		/* Merge server configuration. */
	badge_cmds,			/* Command table. */
	badge_register_hooks		/* Register hooks. */
};
