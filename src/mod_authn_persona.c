/* Copyright 1999-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Based in part, on mod_auth_memcookie, made by Mathieu CARBONNEAUX.
 *
 * See http://authmemcookie.sourceforge.net/ for details;
 * licensed under Apache License, Version 2.0.
 *
 * SHA-1 implementation by Steve Reid, steve@edmweb.com, in
 * public domain.
 */

#include "defines.h"
#include "cookie.h"
#include "config.h"
#include "verify.h"
#include "signin_page.h"

#include <stdio.h>
#include <string.h>
#define APR_WANT_STRFUNC
#include <apr_want.h>
#include <apr_strings.h>
#include <apr_uuid.h>
#include <apr_tables.h>

#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>   /* for ap_hook_(check_user_id | auth_checker)*/
#include <apr_base64.h>

#include <yajl/yajl_tree.h>
#include <curl/curl.h>
#include <curl/easy.h>


/* apache module name */
module AP_MODULE_DECLARE_DATA authn_persona_module;

/** Given a filename and username, open the file (using normal Apache
 * configuration directory search rules) and search for the given username
 * in it (as a newline-seaparated list) */
static int user_in_file(request_rec *r, char *username, char *filename)
{
  apr_status_t status;
  char l[MAX_STRING_LEN];
  ap_configfile_t *f;
  status = ap_pcfg_openfile(&f, r->pool, filename);
  if (status != APR_SUCCESS) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                  "Could not open user file: %s", filename);
    return 0;
  }

  int found = 0;
  while (!(ap_cfg_getline(l, MAX_STRING_LEN, f))) {
    /* Skip # or blank lines. */
    if ((l[0] == '#') || (!l[0])) {
      continue;
    }

    if (!strcmp(username, l)) {
      found = 1;
      break;
    }
  }
  ap_cfg_closefile(f);
  return found;
}

/**************************************************
 * Authentication phase
 *
 * Pull the cookie from the header and verify it.
 **************************************************/
static int Auth_browserid_check_cookie(request_rec *r)
{
  BrowserIDConfigRec *conf=NULL;
  char *szCookieValue=NULL;
  char *szRemoteIP=NULL;
  const char *assertion=NULL;

  ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Auth_browserid_check_cookie");

  /* get apache config */
  conf = ap_get_module_config(r->per_dir_config, &authn_persona_module);

  /* If this is an authentication request providing an assertion, let's process it */
  assertion = apr_table_get(r->headers_in, "X-Persona-Assertion");
  if (assertion) {
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG
                  "Assertion received '%s'", assertion);

    int rez = processAssertion(r, conf, assertion);

    if (rez == OK) {
      /* redirect to the requested resource */
      // 1. set cookie
      // 2. set response code
      // 3. return DONE
      // XXX: write me
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "1 beer");

    // implement me!
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "AuthType are '%s'", ap_auth_type(r));
  unless(strncmp("Persona",ap_auth_type(r),9)==0) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Auth type must be 'Persona'");
    return HTTP_UNAUTHORIZED;
  }

  unless(conf->cookieName) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "No Auth_browserid_CookieName specified");
    return HTTP_UNAUTHORIZED;
  }

  /* get cookie who are named cookieName */
  unless(szCookieValue = extractCookie(r, conf->cookieName))
  {
    ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, ERRTAG "Persona cookie not found; not authorized! RemoteIP:%s",szRemoteIP);

    // XXX: ideally send a 401 here.
    ap_set_content_type(r, "text/html");
    ap_rwrite(src_signin_html, sizeof(src_signin_html), r);

    return DONE;
  }
  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "got cookie; value is %s", szCookieValue);

  /* Check cookie validity */
  if (validateCookie(r, conf, szCookieValue)) {
    ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r, ERRTAG "Invalid Persona cookie: %s", szCookieValue);

    // XXX: ideally send a 401 here.
    ap_set_content_type(r, "text/html");
    ap_rwrite(src_signin_html, sizeof(src_signin_html), r);

    return DONE;
  }

  /* set REMOTE_USER var for scripts language */
  apr_table_setn(r->subprocess_env,"REMOTE_USER",r->user);

  /* log authorisation ok */
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "Persona authentication ok");

  /* if all is ok return auth ok */
  ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "lots of beer");
  return OK;
}


/**************************************************
 * Authentication hook for Apache
 *
 * If the cookie is present, extract it and verify it.
 *
 * if it is valid, apply per-resource authorization rules.
 **************************************************/
static int Auth_browserid_check_auth(request_rec *r)
{
  BrowserIDConfigRec *conf=NULL;
  char *szUser;
  const apr_array_header_t *reqs_arr=NULL;
  require_line *reqs=NULL;
  register int x;
  const char *szRequireLine;
  char *szFileName;
  char *szRequire_cmd;

  ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Auth_browserid_check_auth");

  /* get apache config */
  conf = ap_get_module_config(r->per_dir_config, &authn_persona_module);

  /* get require line */
  reqs_arr = ap_requires(r);
  reqs = reqs_arr ? (require_line *) reqs_arr->elts : NULL;

  /* decline if no require line found */
  if (!reqs_arr) return DECLINED;

  /* walk through the array to check each require command */
  for (x = 0; x < reqs_arr->nelts; x++) {

    if (!(reqs[x].method_mask & (AP_METHOD_BIT << r->method_number)))
      continue;

    /* get require line */
    szRequireLine = reqs[x].requirement;
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "Require Line is '%s'", szRequireLine);

    /* get the first word in require line */
    szRequire_cmd = ap_getword_white(r->pool, &szRequireLine);
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG "Require Cmd is '%s'", szRequire_cmd);

    /* if require cmd are valid-user, they are already authenticated than allow and return OK */
    if (!strcmp("valid-user",szRequire_cmd)) {
      ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG "Require Cmd valid-user");
      return OK;
    }
    /* check the required user */
    else if (!strcmp("user",szRequire_cmd)) {
      szUser = ap_getword_conf(r->pool, &szRequireLine);
      if (strcmp(r->user, szUser)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r ,ERRTAG  "user '%s' is not the required user '%s'",r->user, szUser);
        return HTTP_FORBIDDEN;
      }
      ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r ,ERRTAG  "user '%s' is authorized",r->user);
      return OK;
    }
    /* check for users in a file */ 
    else if (!strcmp("userfile",szRequire_cmd)) {
      szFileName = ap_getword_conf(r->pool, &szRequireLine);
      if (!user_in_file(r, r->user, szFileName)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r ,ERRTAG  "user '%s' is not in username list at '%s'",r->user,szFileName);
        return HTTP_FORBIDDEN;
      } else {
        return OK;
      }
    }
  }
  ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r ,ERRTAG  "user '%s' is not authorized",r->user);
  /* forbid by default */
  return HTTP_FORBIDDEN;
}

/* Parse x-www-url-formencoded args */
apr_table_t *parseArgs(request_rec *r, char *argStr)
{
  char* pair ;
  char* last = NULL ;
  char* eq ;

  apr_table_t *vars = apr_table_make(r->pool, 10) ;
  char *delim = "&";

  for ( pair = apr_strtok(r->args, delim, &last) ;
        pair ;
        pair = apr_strtok(NULL, delim, &last) )
  {
    for (eq = pair ; *eq ; ++eq)
      if ( *eq == '+' )
        *eq = ' ' ;

    ap_unescape_url(pair) ;
    eq = strchr(pair, '=') ;

    if ( eq ) {
      *eq++ = 0 ;
      apr_table_merge(vars, pair, eq) ;
    } else {
      apr_table_merge(vars, pair, "") ;
    }
  }
  return vars;
}

static int processLogout(request_rec *r, BrowserIDConfigRec *conf)
{
  apr_table_set(r->err_headers_out, "Set-Cookie",
                apr_psprintf(r->pool, "%s=; Path=/; Expires=Thu, 01-Jan-1970 00:00:01 GMT",
                             conf->cookieName));

  if (r->args) {
    if ( strlen(r->args) > 16384 ) {
      return HTTP_REQUEST_URI_TOO_LARGE ;
    }

    apr_table_t *vars = parseArgs(r, r->args);
    const char *returnto = apr_table_get(vars, "returnto") ;
    if (returnto) {
      apr_table_set(r->headers_out,"Location", returnto);
      return HTTP_TEMPORARY_REDIRECT;
    }
  }
  apr_table_set(r->headers_out,"Location", "/");
  return HTTP_TEMPORARY_REDIRECT;
}

/**************************************************
 * register module hooks
 **************************************************/
static void register_hooks(apr_pool_t *p)
{
  // these hooks are are executed in order, first is first.
  ap_hook_check_user_id(Auth_browserid_check_cookie, NULL, NULL, APR_HOOK_FIRST);
  ap_hook_auth_checker(Auth_browserid_check_auth, NULL, NULL, APR_HOOK_FIRST);
}

/************************************************************************************
 *  Apache CONFIG Phase:
 ************************************************************************************/
static void *create_browserid_config(apr_pool_t *p, char *d)
{
  BrowserIDConfigRec *conf = apr_palloc(p, sizeof(*conf));
  memset((void *) conf, 0, sizeof(*conf));

  conf->cookieName = apr_pstrdup(p,"BrowserID");
  conf->serverSecret = "BrowserIDSecret";
  conf->forwardedRequestHeader = NULL; /* pass the authenticated user, signed, as an HTTP header */

  return conf;
}

/* apache config fonction of the module */
static const command_rec Auth_browserid_cmds[] =
{
  AP_INIT_TAKE1 (
    "AuthBrowserIDSetHTTPHeader", ap_set_string_slot,
    (void *)APR_OFFSETOF(BrowserIDConfigRec, forwardedRequestHeader),
    OR_AUTHCFG, "Set to 'yes' to forward a signed HTTP header containing the verified identity; set to 'no' by default"),

  AP_INIT_TAKE1(
    "AuthBrowserIDCookieName", ap_set_string_slot,
    (void *)APR_OFFSETOF(BrowserIDConfigRec, cookieName),
    OR_AUTHCFG, "Name of cookie to set"),

  AP_INIT_FLAG (
    "AuthBrowserIDVerifyLocally", ap_set_flag_slot,
    (void *)APR_OFFSETOF(BrowserIDConfigRec, verifyLocally),
    OR_AUTHCFG, "Set to 'yes' to verify assertions locally; ignored if VerificationServerURL is set"),

  AP_INIT_TAKE1 (
    "AuthBrowserIDSecret", ap_set_string_slot,
    (void *)APR_OFFSETOF(BrowserIDConfigRec, serverSecret),
    OR_AUTHCFG, "Server secret for authentication cookie."),

  {NULL}
};

/* apache module structure */
module AP_MODULE_DECLARE_DATA authn_persona_module =
{
  STANDARD20_MODULE_STUFF,
  create_browserid_config,    /* dir config creator */
  NULL,                       /* dir merger --- default is to override */
  NULL,                       /* server config */
  NULL,                       /* merge server config */
  Auth_browserid_cmds,        /* command apr_table_t */
  register_hooks              /* register hooks */
};
