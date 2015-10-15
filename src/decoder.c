/**
***	Badge decoder handler: display badge data.
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

#include "mod_badge.h"


int
badge_decoder_handler(request_rec * r)

{
	char * badge;
	int len;
	char * errmsg;
	apr_array_header_t * keys;
	badge_entry * * bep;
	badge_entry * e;
	char * myself;
	int i;
	badge_data b;

	/**
	***	Read a badge, decode and show it.
	**/

	keys = NULL;
	e = NULL;
	badge_parse_query(r, "badge", &badge, 1, NULL);

	/**
	***	Validate input.
	**/

	errmsg = NULL;

	if (badge) {
		len = badge_length(badge);

		if (!len || badge[len])
			errmsg = "Please enter a valid badge string";
		else {
			/* Try to decode badge. */

			keys = badge_unique_key_files(r->pool,
			    ap_get_module_config(r->per_dir_config,
			    &badge_module));
			bep = (badge_entry * *) keys->elts;
			errmsg = "Cannot decode this badge with "
			    "one of the configured keys";

			for (i = 0; i < keys->nelts; i++)
				if (badge_decode(&b, badge, e = *bep++, r)) {
					errmsg = NULL;
					break;
					}
			}
		}

	/**
	***	Start the output page.
	**/

	myself = ap_escape_html(r->pool, r->uri);
	ap_set_content_type(r, "text/html");
	ap_rvputs(r, DOCTYPE_HTML_4_0S,
	    "<html>\n",
	    " <head>\n",
	    "  <title>Decode a badge</title>\n",
	    "  <style type=\"text/css\">\n",
	    "   <!--\n",
	    "    .err { background-color: red; }\n",
	    "   -->\n",
	    "  </style>\n",
	    " </head>\n",
	    " <body>\n",
	    "<h1>Badge decoder</h1>\n", NULL);

	/**
	***	If we succeed in decoding, show the results.
	**/

	if (badge && !errmsg) {
		badge_show(r, &b, badge, e->sslfile, NULL, NULL, NULL, keys, 0);
		ap_rvputs(r,
		    "<a href=\"", ap_escape_html(r->pool, r->uri),
		    "\">Decode another badge</a>\n", NULL);
		}
	else {
		/**
		***	Draw the input form.
		**/

		if (!badge)
			badge = "";
		else
			badge = ap_escape_html(r->pool, badge);

		ap_rvputs(r,
		    "<form method=\"get\" action=\"", myself, "\">\n",
		    "<p>Enter a badge to decode&nbsp;",
		    "<input type=\"text\" name=\"badge\" value=\"", badge, "\"",
		    badge_arg_err(errmsg != NULL), " /></p>\n",
		    "<input type=\"submit\" value=\"Decode this badge\" />",
		    "</form>\n", NULL);

		if (errmsg)
			ap_rvputs(r, "<br /><p><span", badge_arg_err(1), ">",
			    errmsg, "</span></p>\n", NULL);
		}

	ap_rvputs(r, " </body>\n", "</html>\n", NULL);
	return OK;
}
