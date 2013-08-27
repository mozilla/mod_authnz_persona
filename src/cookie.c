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

#include <stdio.h>
#include <string.h>
#define APR_WANT_STRFUNC

#include <apr_want.h>
#include <apr_strings.h>
#include <apr_sha1.h>
#include <apr_base64.h>

#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>

#include "cookie.h"
#include "defines.h"

/** Generates a signature with the given inputs, returning a Base64-encoded
 * signature value. */
static char *generateSignature(request_rec *r, char *userAddress)
{
  apr_sha1_ctx_t context;
  apr_sha1_init(&context);
  apr_sha1_update(&context, userAddress, strlen(userAddress));
  apr_sha1_update(&context, PERSONA_SERVER_SECRET, strlen(PERSONA_SERVER_SECRET));
  unsigned char digest[20];
  apr_sha1_final(digest, &context);

  char * digest64 = apr_palloc(r->pool, apr_base64_encode_len(20));
  apr_base64_encode(digest64, (char*)digest, 20);
  return digest64;
}

/* Look through the 'Cookie' headers for the indicated cookie; extract it
 * and URL-unescape it. Return the cookie on success, NULL on failure. */
char * extractCookie(request_rec *r, const char *szCookie_name) 
{
  char *szRaw_cookie_start=NULL, *szRaw_cookie_end;
  char *szCookie;
  /* get cookie string */
  char*szRaw_cookie = (char*)apr_table_get( r->headers_in, "Cookie");
  unless(szRaw_cookie) return 0;

  /* loop to search cookie name in cookie header */
  do {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "Checking cookie %s, looking for %s", szRaw_cookie, szCookie_name);

    /* search cookie name in cookie string */
    unless (szRaw_cookie =strstr(szRaw_cookie, szCookie_name)) return 0;
    szRaw_cookie_start=szRaw_cookie;
    /* search '=' */
    unless (szRaw_cookie = strchr(szRaw_cookie, '=')) return 0;
  } while (strncmp(szCookie_name,szRaw_cookie_start,szRaw_cookie-szRaw_cookie_start)!=0);

  /* skip '=' */
  szRaw_cookie++;

  /* search end of cookie name value: ';' or end of cookie strings */
  unless ((szRaw_cookie_end = strchr(szRaw_cookie, ';')) || (szRaw_cookie_end = strchr(szRaw_cookie, '\0'))) return 0;

  /* dup the value string found in apache pool and set the result pool ptr to szCookie ptr */
  unless (szCookie = apr_pstrndup(r->pool, szRaw_cookie, szRaw_cookie_end-szRaw_cookie)) return 0;
  /* unescape the value string */ 
  unless (ap_unescape_url(szCookie) == 0) return 0;

  ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "finished cookie scan, returning %s", szCookie);

  return szCookie;
}

/* Check the cookie and make sure it is valid */
int validateCookie(request_rec *r, char *szCookieValue)
{
  /* split at | */
  char *sig = NULL;
  char *addr = apr_strtok(szCookieValue, "|", &sig);
  if (!addr) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "malformed BrowserID cookie");
    return 1;
  }

  char *digest64 = generateSignature(r, addr);
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "Got cookie: email is %s; expected digest is %s; got digest %s",
                addr, digest64, sig);

  /* paranoia indicates that we should use a time-invariant compare here */
  if (strcmp(digest64, sig)) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "invalid BrowserID cookie");
    free(digest64);
    return 1;
  }

  /* Cookie is good: set r->user */
  r->user = (char*)addr;
  return 0;
}

/** Create a session cookie with a given identity */
void createSessionCookie(request_rec *r, char *identity)
{
  char *digest64 = generateSignature(r, identity);

  /* syntax of cookie is identity|signature */
  apr_table_set(r->err_headers_out, "Set-Cookie",
                apr_psprintf(r->pool, "%s=%s|%s; Path=/",
                             PERSONA_COOKIE_NAME, identity, digest64));
}
