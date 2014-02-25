/* Copyright 1999-2014 The Apache Software Foundation
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

#include <assert.h>
#include <string.h>

#include <apr_errno.h>
#include <apr_general.h>
#include <apr_hooks.h>
#include <apr_pools.h>
#include <apr_random.h>
#include <apr_strings.h>
#include <apr_tables.h>

#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>   /* for ap_hook_(check_user_id | auth_checker)*/

#include <ap_config.h>
#include <ap_mmn.h>
#if AP_MODULE_MAGIC_AT_LEAST(20080403, 1)
#include "mod_auth.h"
#endif

#include "defines.h"
#include "cookie.h"
#include "verify.h"
#include "signin_page.h"
#include "error_page.h"

/* apache module name */
module AP_MODULE_DECLARE_DATA authnz_persona_module;

static int persona_authn_active(request_rec *r) {
  return (strncmp("Persona", ap_auth_type(r), 9) == 0) ? 1 : 0;
}

/* Parse x-www-url-formencoded args */
apr_table_t *parse_args(request_rec *r, char *args) {

  char* pair;
  char* last = NULL;
  char* eq;
  char *delim = "&";

  apr_table_t *vars = apr_table_make(r->pool, 10);
  for (pair = apr_strtok(r->args, delim, &last); pair; pair = apr_strtok(NULL, delim, &last)) {

    for (eq = pair; *eq; ++eq)
      if (*eq == '+')
        *eq = ' ';

    ap_unescape_url(pair);
    eq = strchr(pair, '=');
    if (eq) {
      *eq++ = 0;
      apr_table_merge(vars, pair, eq);
    } else {
      apr_table_merge(vars, pair, "");
    }

  }

  return vars;

}

static int process_logout(request_rec *r) {

  const char *returnto = NULL;
  sendResetCookie(r);
  if (r->args) {
    if (strlen(r->args) > 16384)
      return HTTP_REQUEST_URI_TOO_LARGE;
    returnto = apr_table_get(parse_args(r, r->args), "returnto");
  }

  apr_table_set(r->headers_out, "Location", returnto == NULL ? "/" : returnto);
  return HTTP_SEE_OTHER;

}

/**************************************************
 * Authentication phase
 *
 * - If AuthType != Persona, do nothing
 * - Handle POSTed assertions ("null" -> logout)
 * - If we have a cookie, set up user context
 **************************************************/
static int Auth_persona_check_cookie(request_rec *r)
{
  char *szCookieValue=NULL;
  char *szRemoteIP=NULL;
  const char *assertion=NULL;

  if (!persona_authn_active(r)) {
    return DECLINED;
  }
  ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Auth_persona_check_cookie");

  // We'll trade you a valid assertion for a session cookie!
  // this is a programmatic XHR request.

  persona_config_t *conf = ap_get_module_config(r->server->module_config, &authnz_persona_module);
  assertion = apr_table_get(r->headers_in, PERSONA_ASSERTION_HEADER);
  if (assertion) {

    if (strcmp(r->method, "POST")) {
      r->status = HTTP_METHOD_NOT_ALLOWED;
      ap_set_content_type(r, "application/json");
      const char *error = "{\"status\": \"failure\", \"reason\":"
                          "\"login must be performed with POST\"}";
      ap_rwrite(error, strlen(error), r);
      return DONE;
    }

    if (!strcmp(assertion, "null")) {
      sendResetCookie(r);
      r->status = HTTP_OK;
      const char *status = "{\"status\": \"okay\"}";
      ap_set_content_type(r, "application/json");
      ap_rwrite(status, strlen(status), r);
      return DONE;
    }

    VerifyResult res = processAssertion(r, assertion);
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG
                  "Assertion received '%s'", assertion);

    if (res->verifiedEmail) {
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r, ERRTAG
                    "email '%s' verified, vouched for by issuer '%s'",
                    res->verifiedEmail, res->identityIssuer);
      Cookie cookie = apr_pcalloc(r->pool, sizeof(struct _Cookie));
      cookie->verifiedEmail = res->verifiedEmail;
      cookie->identityIssuer = res->identityIssuer;
      cookie->created = apr_time_sec(r->request_time);
      sendSignedCookie(r, conf->secret, cookie);
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

  // handle logout via LogoutPath hit before letting valid cookies through
  if (conf->logout_path->len && !strncmp(r->uri, conf->logout_path->data, conf->logout_path->len)) {
    return process_logout(r);
  }

  // if there's a valid cookie, allow the user through
  szCookieValue = extractCookie(r, conf->secret, PERSONA_COOKIE_NAME);

  Cookie cookie = NULL;
  if (szCookieValue &&
      (cookie = validateCookie(r, conf->secret, szCookieValue))) {
    r->user = (char *) cookie->verifiedEmail;
    apr_table_setn(r->notes, PERSONA_ISSUER_NOTE, cookie->identityIssuer);
    apr_table_setn(r->subprocess_env, "REMOTE_USER", cookie->verifiedEmail);
    ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, ERRTAG "Valid auth cookie found, passthrough");
    ap_custom_response(r, 401, (const char*) build_error_html);
    ap_custom_response(r, 403, (const char*) build_error_html);
    return OK;
  }

  ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, ERRTAG "Persona cookie not found; not authorized! RemoteIP:%s",szRemoteIP);
  r->status = HTTP_UNAUTHORIZED;
  ap_set_content_type(r, "text/html");
  ap_rwrite(src_signin_html, sizeof(src_signin_html), r);
  ap_rprintf(r, "var loggedInUser = undefined;\n");
  ap_rwrite(PERSONA_END_PAGE, sizeof(PERSONA_END_PAGE), r);
  return DONE;
}

#if !AP_MODULE_MAGIC_AT_LEAST(20080403, 1)

/**************************************************
 * Authorization phase (Apache 2.2)
 *
 * Requires authentication phase to run first.
 *
 * Handles Require persona-idp directives.
 **************************************************/
static int Auth_persona_check_auth(request_rec *r)
{
  const apr_array_header_t *reqs_arr=NULL;
  require_line *reqs=NULL;
  register int x;
  const char *szRequireLine;
  char *szRequire_cmd;

  if (!persona_authn_active(r)) {
    return DECLINED;
  }
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

    // persona-idp: check host part of user name
    if (!strcmp("persona-idp", szRequire_cmd)) {
      char *reqIdp = ap_getword_conf(r->pool, &szRequireLine);
      const char *issuer = apr_table_get(r->notes, PERSONA_ISSUER_NOTE);
      if (!issuer || strcmp(issuer, reqIdp)) {
        return HTTP_FORBIDDEN;
      }
      ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r,
                    ERRTAG "user '%s' is authorized", r->user);
      return OK;
    }

  }
  return DECLINED;
}

#else

/**************************************************
 * Authorization phase (Apache 2.4)
 *
 * Handles Require persona-idp directives.
 *
 * When this is first called, the authentication context hasn't been setup
 * yet. Return AUTHZ_DENIED_NO_USER to force it to run, then this will be
 * called again, with the context setup.
 **************************************************/
static authz_status persona_idp_check_authorization(request_rec *r,
                                                    const char *require_args,
                                                    const void *parsed_require_args) {

  ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Require persona-idp");
  if (!r->user)
    // this triggers running authn hook, which we need
    return AUTHZ_DENIED_NO_USER;

  char *reqIdp = ap_getword_white(r->pool, &require_args);
  const char *issuer = apr_table_get(r->notes, PERSONA_ISSUER_NOTE);
  return issuer && !strcmp(issuer, reqIdp) ? AUTHZ_GRANTED : AUTHZ_DENIED;
}

static const authz_provider authz_persona_idp_provider =
{
  &persona_idp_check_authorization,
  NULL,
};

#endif

/**************************************************
 * register module hooks
 **************************************************/

static void register_hooks(apr_pool_t *p)
{
  // these hooks are executed in order, first is first.
#if AP_MODULE_MAGIC_AT_LEAST(20080403, 1)
  ap_hook_check_authn(Auth_persona_check_cookie, NULL, NULL, APR_HOOK_FIRST,
                      AP_AUTH_INTERNAL_PER_CONF);
  ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "persona-idp",
                            AUTHZ_PROVIDER_VERSION, &authz_persona_idp_provider,
                            AP_AUTH_INTERNAL_PER_CONF);
#else
  ap_hook_check_user_id(Auth_persona_check_cookie, NULL, NULL, APR_HOOK_FIRST);
  ap_hook_auth_checker(Auth_persona_check_auth, NULL, NULL, APR_HOOK_FIRST);
#endif
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

  conf->logout_path = apr_palloc(p, sizeof(buffer_t));
  conf->logout_path->len = 0;
  conf->logout_path->data = NULL;

  return conf;
}

const char* persona_server_secret_option(cmd_parms *cmd, void *cfg, const char *arg) {
  server_rec *s = cmd->server;
  persona_config_t *conf = ap_get_module_config(s->module_config, &authnz_persona_module);
  conf->secret->len = strlen(arg);
  conf->secret->data = apr_palloc(cmd->pool, conf->secret->len);
  strncpy(conf->secret->data, arg, conf->secret->len);
  return NULL;
}

const char* persona_logout_path(cmd_parms *cmd, void *cfg, const char *arg) {
  server_rec *s = cmd->server;
  persona_config_t *conf = ap_get_module_config(s->module_config, &authnz_persona_module);
  conf->logout_path->len = strlen(arg);
  conf->logout_path->data = apr_palloc(cmd->pool, conf->logout_path->len);
  strncpy(conf->logout_path->data, arg, conf->logout_path->len);
  return NULL;
}

static const command_rec Auth_persona_options[] =
{
  AP_INIT_TAKE1(
    "AuthPersonaServerSecret", persona_server_secret_option,
    NULL, RSRC_CONF, "Server secret to use for cookie signing"
  ),
  AP_INIT_TAKE1(
    "AuthPersonaLogoutPath", persona_logout_path,
    NULL, RSRC_CONF, "Path used to trigger logout"
  ),
  {NULL}
};

/* apache module structure */
module AP_MODULE_DECLARE_DATA authnz_persona_module =
{
  STANDARD20_MODULE_STUFF,
  NULL,                       /* dir config creator */
  NULL,                       /* dir merger --- default is to override */
  persona_create_svr_config,  /* server config creator */
  NULL,                       /* merge server config */
  Auth_persona_options,       /* command apr_table_t */
  register_hooks              /* register hooks */
};
