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
#include "verify.h"
#include "signin_page.h"

#include <stdio.h>
#include <string.h>
#define APR_WANT_STRFUNC
#include <apr_want.h>
#include <apr_strings.h>
#include <apr_uuid.h>
#include <apr_tables.h>
#include <apr_random.h>

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
#include <assert.h>

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
static int Auth_persona_check_cookie(request_rec *r)
{
  char *szCookieValue=NULL;
  char *szRemoteIP=NULL;
  const char *assertion=NULL;

  ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Auth_persona_check_cookie");

  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "AuthType '%s'", ap_auth_type(r));
  if (strncmp("Persona", ap_auth_type(r), 9) != 0) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Auth type must be 'Persona'");
    return HTTP_UNAUTHORIZED;
  }

  // if there's a valid cookie, allow the user throught
  persona_config_t *conf = ap_get_module_config(r->server->module_config, &authn_persona_module);
  szCookieValue = extractCookie(r, conf->secret, PERSONA_COOKIE_NAME);

  char *verifiedEmail = validateCookie(r, conf->secret, szCookieValue);
  if (szCookieValue && verifiedEmail) {
    r->user = verifiedEmail;
    apr_table_setn(r->subprocess_env, "REMOTE_USER", verifiedEmail);
    ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, ERRTAG "Valid auth cookie found, passthrough");
    return OK;
  }

  // We'll trade you a valid assertion for a session cookie!
  // this is a programatic XHR request.

  // XXX: only test for post - issue #10

  assertion = apr_table_get(r->headers_in, PERSONA_ASSERTION_HEADER);
  if (assertion) {
    VerifyResult res = processAssertion(r, assertion);

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG
                  "Assertion received '%s'", assertion);

    if (res->verifiedEmail) {
      createSessionCookie(r, conf->secret, res->verifiedEmail);
      return DONE;
    } else {
      assert(res->errorResponse != NULL);

      r->status = HTTP_INTERNAL_SERVER_ERROR;
      ap_set_content_type(r, "application/json");
      ap_rwrite(res->errorResponse, strlen(res->errorResponse), r);

      // upon assertion verification failure we return JSON explaining why
      return DONE;
    }
  }

  ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, ERRTAG "Persona cookie not found; not authorized! RemoteIP:%s",szRemoteIP);
  r->status = HTTP_UNAUTHORIZED;
  ap_set_content_type(r, "text/html");
  ap_rwrite(src_signin_html, sizeof(src_signin_html), r);
  return DONE;
}


/**************************************************
 * Authentication hook for Apache
 *
 * If the cookie is present, extract it and verify it.
 *
 * if it is valid, apply per-resource authorization rules.
 **************************************************/
static int Auth_persona_check_auth(request_rec *r)
{
  char *szUser;
  const apr_array_header_t *reqs_arr=NULL;
  require_line *reqs=NULL;
  register int x;
  const char *szRequireLine;
  char *szFileName;
  char *szRequire_cmd;

  ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Auth_persona_check_auth");

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

static int processLogout(request_rec *r)
{
  apr_table_set(r->err_headers_out, "Set-Cookie",
                apr_psprintf(r->pool, "%s=; Path=/; Expires=Thu, 01-Jan-1970 00:00:01 GMT",
                             PERSONA_COOKIE_NAME));

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
  ap_hook_check_user_id(Auth_persona_check_cookie, NULL, NULL, APR_HOOK_FIRST);
  ap_hook_auth_checker(Auth_persona_check_auth, NULL, NULL, APR_HOOK_FIRST);
}

#define RAND_BYTES_AT_A_TIME 256
static void *persona_create_svr_config(apr_pool_t *p, server_rec *s)
{
  persona_config_t *conf = apr_palloc(p, sizeof(*conf));
  apr_random_t *prng = apr_random_standard_new(p);
  while (apr_random_secure_ready(prng) == APR_ENOTENOUGHENTROPY) {
    unsigned char randbuf[RAND_BYTES_AT_A_TIME];
    apr_generate_random_bytes(randbuf, RAND_BYTES_AT_A_TIME);
    apr_random_add_entropy(prng, randbuf, RAND_BYTES_AT_A_TIME);
  }
  char *secret = apr_palloc(p, PERSONA_SECRET_SIZE);
  apr_random_secure_bytes(prng, secret, PERSONA_SECRET_SIZE);
  conf->secret = apr_palloc(p, sizeof(buffer_t));
  conf->secret->len = PERSONA_SECRET_SIZE;
  conf->secret->data = secret;
  return conf;
}

const char* persona_server_secret_option(cmd_parms *cmd, void *cfg, const char *arg) {
  server_rec *s = cmd->server;
  persona_config_t *conf = ap_get_module_config(s->module_config, &authn_persona_module);
  conf->secret->len = strlen(arg);
  conf->secret->data = apr_palloc(cmd->pool, conf->secret->len);
  strncpy(conf->secret->data, arg, conf->secret->len);
  return NULL;
}

static const command_rec Auth_persona_options[] =
{
  AP_INIT_TAKE1(
    "AuthPersonaServerSecret", persona_server_secret_option,
    NULL, RSRC_CONF, "Server secret to use for cookie signing"
  ),
  {NULL}
};

/* apache module structure */
module AP_MODULE_DECLARE_DATA authn_persona_module =
{
  STANDARD20_MODULE_STUFF,
  NULL,                       /* dir config creator */
  NULL,                       /* dir merger --- default is to override */
  persona_create_svr_config,  /* server config creator */
  NULL,                       /* merge server config */
  Auth_persona_options,       /* command apr_table_t */
  register_hooks              /* register hooks */
};
