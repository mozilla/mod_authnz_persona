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


/* function to fix any headers in the input request that may be relied on by an
   application. e.g. php uses the Authorization header when logging the request
   in apache and not r->user (like it ought to). It is applied after the request
   has been authenticated. */
static void fix_headers_in(request_rec *r,char*szPassword)
{
  char *szUser=NULL;
  /* Set an Authorization header in the input request table for php and
     other applications that use it to obtain the username (mainly to fix
     apache logging of php scripts). We only set this if there is no header
     already present. */

  if (apr_table_get(r->headers_in,"Authorization")==NULL) 
  {
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, ERRTAG "fixing apache Authorization header for this request using user: %s",r->user);

    /* concat username and ':' */
    if (szPassword!=NULL) szUser=(char*)apr_pstrcat(r->pool,r->user,":",szPassword,NULL);
    else szUser=(char*)apr_pstrcat(r->pool,r->user,":",NULL);

    /* alloc memory for the estimated encode size of the username */
    char *szB64_enc_user=(char*)apr_palloc(r->pool,apr_base64_encode_len(strlen(szUser))+1);
    unless (szB64_enc_user) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "memory alloc failed!");
      return;
    }

    /* encode username in base64 format */
    apr_base64_encode(szB64_enc_user,szUser,strlen(szUser));

    /* set authorization header */
    apr_table_set(r->headers_in,"Authorization", (char*)apr_pstrcat(r->pool,"Basic ",szB64_enc_user,NULL));

    /* force auth type to basic */
    r->ap_auth_type=apr_pstrdup(r->pool,"Basic");
  }

  return;
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
  assertion = apr_table_get(r->headers_in, "X-BrowserID-Assertion");
  if (assertion) {
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG
                  "Assertion recieved '%s'", assertion);

    int rez = processAssertion(r, conf, assertion);

    if (rez == OK) {
      /* redirect to the requested resource */
      // 1. set cookie
      // 2. set response code
      // 3. return DONE
      // XXX: write me
    }

    // implement me!
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  /* XXX: is this really right?  at what point will the cookie be checked?  This looks like a bug.
   *  is mis-implemented here - it being set to no should not prevent us from checking the cookie */
  unless(conf->authoritative)
    return DECLINED;

  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "AuthType are '%s'", ap_auth_type(r));
  unless(strncmp("BrowserID",ap_auth_type(r),9)==0) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Auth type must be 'BrowserID'");
    return HTTP_UNAUTHORIZED;
  }

  unless(conf->cookieName) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "No Auth_browserid_CookieName specified");
    return HTTP_UNAUTHORIZED;
  }

  /* get cookie who are named cookieName */
  unless(szCookieValue = extractCookie(r, conf->cookieName))
  {
    ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, ERRTAG "BrowserID cookie not found; not authorized! RemoteIP:%s",szRemoteIP);
    return HTTP_UNAUTHORIZED;
  }
  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "got cookie; value is %s", szCookieValue);

  /* Check cookie validity */
  if (validateCookie(r, conf, szCookieValue)) {
    ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r, ERRTAG "Invalid BrowserID cookie: %s", szCookieValue);
    return HTTP_UNAUTHORIZED;
  }

  /* set REMOTE_USER var for scripts language */
  apr_table_setn(r->subprocess_env,"REMOTE_USER",r->user);

  /* log authorisation ok */
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "BrowserID authentication ok");

  /* fix http header for php */
  if (conf->authBasicFix) fix_headers_in(r,"browserid");

  /* if all is ok return auth ok */
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

  /* check if this module is authoritative */
  unless(conf->authoritative)
    return DECLINED;

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


/* Called from the fixup_handler when we receive a form submission.
 *
 * XXX handle POST submissions correctly - this will take some work,
 *     as we have to loop to handle chunked submissions
 */
static int processAssertionFormSubmit(request_rec *r, BrowserIDConfigRec *conf)
{
  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG "Submission to BrowserID form handler");

  /* parse the form and extract the assertion */
  if (r->method_number == M_GET) {
    if ( r->args ) {
      if ( strlen(r->args) > 16384 ) {
        return HTTP_REQUEST_URI_TOO_LARGE ;
      }

      apr_table_t *vars = parseArgs(r, r->args);
      const char *assertionParsed = apr_table_get(vars, "assertion") ;
      const char *returnto = apr_table_get(vars, "returnto") ;
      ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG
                    "In post_read_request; parsed assertion as %s", assertionParsed);
      ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG
                    "In post_read_request; parsed returnto as %s", returnto);

      int rez = processAssertion(r, conf, assertionParsed);

      if (rez == OK) {
        /* redirect to the requested resource */
        apr_table_set(r->headers_out,"Location", returnto);
        return HTTP_TEMPORARY_REDIRECT;
      }
    }
  } else {
    ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,ERRTAG "In post_read_request; this is a POST - skipping it for now");
  }
  return DECLINED;
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

/*
 * We grab form submissions in the fixup step.  In this step, if the
 * user has submitted an assertion, we need to pull it out, verify it,
 * and create a new session cookie for them.
 *
 * The return value is OK, DECLINED, or HTTP_mumble.  If we return OK, no
 * further modules are called for this phase.
 */
static int Auth_browserid_fixups(request_rec *r)
{
  BrowserIDConfigRec *conf=NULL;

  ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Auth_browserid_fixups");

  /* get apache config */
  conf = ap_get_module_config(r->per_dir_config, &authn_persona_module);

  if (conf->submitPath && !strcmp(r->uri, conf->submitPath)) {
    return processAssertionFormSubmit(r, conf);
  }
  else if (conf->logoutPath && !strcmp(r->uri, conf->logoutPath)) {
    return processLogout(r, conf);
  }

  /* otherwise we don't care */
  return DECLINED;
}


/**************************************************
 * register module hooks
 **************************************************/
static void register_hooks(apr_pool_t *p)
{
  // these hooks are are executed in order, first is first.
  ap_hook_check_user_id(Auth_browserid_check_cookie, NULL, NULL, APR_HOOK_FIRST);
  ap_hook_auth_checker(Auth_browserid_check_auth, NULL, NULL, APR_HOOK_FIRST);
  ap_hook_fixups(Auth_browserid_fixups, NULL, NULL, APR_HOOK_FIRST);
}

/************************************************************************************
 *  Apache CONFIG Phase:
 ************************************************************************************/
static void *create_browserid_config(apr_pool_t *p, char *d)
{
  BrowserIDConfigRec *conf = apr_palloc(p, sizeof(*conf));

  conf->cookieName = apr_pstrdup(p,"BrowserID");
  conf->submitPath = "/mod_browserid_submit";
  conf->serverSecret = "BrowserIDSecret";
  conf->logoutPath = NULL;
  conf->authoritative = 0;  /* not by default */
  conf->authBasicFix = 0;  /* do not fix header for php auth by default */
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
    "AuthBrowserIDAuthoritative", ap_set_flag_slot,
    (void *)APR_OFFSETOF(BrowserIDConfigRec, authoritative),
    OR_AUTHCFG, "Set to 'yes' to allow access control to be passed along to lower modules; set to 'no' by default"),

  AP_INIT_FLAG (
    "AuthBrowserIDSimulateAuthBasic", ap_set_flag_slot,
    (void *)APR_OFFSETOF(BrowserIDConfigRec, authBasicFix),
    OR_AUTHCFG, "Set to 'yes' to enable creation of a synthetic Basic Authorization header containing the username"),

  AP_INIT_TAKE1 (
    "AuthBrowserIDSubmitPath", ap_set_string_slot,
    (void *)APR_OFFSETOF(BrowserIDConfigRec, submitPath),
    OR_AUTHCFG, "Path to which login forms will be submitted.  Form must contain a field named 'assertion'"),

  AP_INIT_TAKE1 (
    "AuthBrowserIDLogoutPath", ap_set_string_slot,
    (void *)APR_OFFSETOF(BrowserIDConfigRec, logoutPath),
    OR_AUTHCFG, "Path to which logout requests will be submitted.  An optional 'returnto' parameter will be used for a redirection, if provided."),

  AP_INIT_TAKE1 (
    "AuthBrowserIDVerificationServerURL", ap_set_string_slot,
    (void *)APR_OFFSETOF(BrowserIDConfigRec, verificationServerURL),
    OR_AUTHCFG, "URL of the BrowserID verification server."),

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
