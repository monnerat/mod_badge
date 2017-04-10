/**
***	mod_badge: Apache module interface.
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

#include "mod_badge.h"



static const char *
badge_keep_auth_cmd(cmd_parms * cmd, void * dconfig, int flag)

{
	badge_conf * conf;

	conf = (badge_conf *) dconfig;
	conf->keepauth = flag? 1: -1;
	return NULL;
}


static const char *
badge_map_cmd(cmd_parms * cmd, void * dconfig,
					const char * fake, const char * sslfile)

{
	badge_conf * conf;
	badge_entry * new;

	conf = (badge_conf *) dconfig;
	new = apr_array_push(conf->badges);
	new->fake = badge_canonicalize_path(cmd->pool, "/", fake);
	new->sslfile = ap_server_root_relative(cmd->pool, sslfile);
	new->key = NULL;

	if (!badge_load_key(new))
		return apr_pstrcat(cmd->pool, "BadgeMap: file `", new->sslfile,
		    "' does not exist or does not contain valid SSL data. ",
		    "Directive ignored.", NULL);

	return NULL;
}


static const char *
badge_set_handler_cmd(cmd_parms * cmd, void * dconfig, const char * handler)

{
	const ap_directive_t * dirp;

	/**
	***	Hack: we redefine the SetHandler command to forbid use
	***		of our handlers outside of a <Location.*> section.
	**/

	if (strcmp(handler, "badge-factory") &&
	    strcmp(handler, "badge-decoder"))
		return NULL;

	for (dirp = cmd->directive; (dirp = dirp->parent);)
		if (!strcasecmp(dirp->directive, "<Location") ||
		    !strcasecmp(dirp->directive, "<LocationMatch"))
			return NULL;

	return apr_pstrcat(cmd->pool, cmd->cmd->name, " ", handler,
	    " may only occur in a <Location> or <LocationMatch> section", NULL);
}


static const command_rec	badge_cmds[] = {
	AP_INIT_FLAG("BadgeKeepAuth", badge_keep_auth_cmd, NULL,
	    RSRC_CONF | ACCESS_CONF,
	    "Whether to keep client's authorization or not"),
	AP_INIT_TAKE2("BadgeMap", badge_map_cmd, NULL, RSRC_CONF | ACCESS_CONF,
	    "an URL prefix and a certificate or key filename"),
	AP_INIT_TAKE1("SetHandler", badge_set_handler_cmd, NULL, OR_FILEINFO,
	    "a handler name that overrides any other configured handler"),
	{	NULL	}
};


static void *
create_badge_dir_config(apr_pool_t * p, char * dirspec)

{
	badge_conf * conf;

	conf = (badge_conf *) apr_pcalloc(p, sizeof *conf);
	conf->badges = apr_array_make(p, 20, sizeof(badge_entry));
	return conf;
}


static void *
merge_badge_dir_config(apr_pool_t * p, void * basev, void * overridesv)

{
	badge_conf * conf;
	badge_conf * base;
	badge_conf * overrides;

	conf = (badge_conf *) apr_pcalloc(p, sizeof *conf);
	base = (badge_conf *) basev;
	overrides = (badge_conf *) overridesv;
	conf->keepauth =
	    overrides->keepauth? overrides->keepauth: base->keepauth;
	conf->badges = apr_array_append(p, overrides->badges, base->badges);
	return conf;
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
badge_translate_name(request_rec * r)

{
	char * uri;
	int status;

	uri = r->uri;
	status = badge_map(r);

	if (status != DECLINED)
		apr_table_setn(r->notes, BADGE_URI, uri);

	if (status == OK)
		status = DECLINED;		/* Continue translation. */

	return status;
}


static int
badge_restore_uri(request_rec * r)

{
	const char * uri;

	/**
	***	Must restore URI for subsequent location computation,
	***		subrequests and/or link computations.
	**/

	uri = apr_table_get(r->notes, BADGE_URI);

	if (uri)
		r->uri = (char *) uri;

	return DECLINED;		/* Process other hooks. */
}


static int
badge_handler(request_rec * r)

{
	if (!strcmp(r->handler, "badge-factory"))
		return badge_factory_handler(r);

	if (!strcmp(r->handler, "badge-decoder"))
		return badge_decoder_handler(r);

	return DECLINED;
}


static void
badge_register_hooks(apr_pool_t * p)

{
	static const char * const translate_successors[] = {
		"mod_rewrite.c",
		"mod_alias.c",
		NULL
		};

	ap_hook_post_config(badge_post_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_translate_name(badge_translate_name, NULL,
	    translate_successors, APR_HOOK_FIRST);
	ap_hook_map_to_storage(badge_restore_uri, NULL, NULL, APR_HOOK_FIRST);
	ap_hook_handler(badge_handler, NULL, NULL, APR_HOOK_MIDDLE);
}


module AP_MODULE_DECLARE_DATA	badge_module = {
	STANDARD20_MODULE_STUFF,
	create_badge_dir_config,	/* Create directory configuration. */
	merge_badge_dir_config,		/* Merge directory configuration. */
	NULL,				/* Create server configuration. */
	NULL,				/* Merge server configuration. */
	badge_cmds,			/* Command table. */
	badge_register_hooks		/* Register hooks. */
};
