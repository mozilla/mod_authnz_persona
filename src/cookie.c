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

#include <stdio.h>
#include <string.h>

#include <apr_base64.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_tables.h>

#include <httpd.h>
#include <http_log.h>

#include "cookie.h"
#include "defines.h"
#include "hmac.h"

/** Generates a HMAC with the given inputs, returning a Base64-encoded
 * signature value. */
static char *generateHMAC(request_rec *r, const buffer_t *secret, const Cookie cookie)
{
  char *data;
  unsigned char digest[HMAC_DIGESTSIZE];
  char *digest64;

  char timestr[12];
  snprintf(timestr, 12, "%" APR_TIME_T_FMT, cookie->created);
  data = apr_pstrcat(r->pool, cookie->verifiedEmail, cookie->identityIssuer, timestr, NULL);
  hmac(secret->data, secret->len, data, strlen(data), &digest);
  digest64 = apr_palloc(r->pool, apr_base64_encode_len(HMAC_DIGESTSIZE));
  apr_base64_encode(digest64, (char*)digest, HMAC_DIGESTSIZE);
  return digest64;
}

/* Look through the 'Cookie' headers for the indicated cookie; extract it
 * and URL-unescape it. Return the cookie on success, NULL on failure. */
char * extractCookie(request_rec *r, const buffer_t *secret, const char *szCookie_name)
{
  char *szRaw_cookie_start=NULL, *szRaw_cookie_end;
  char *szCookie;
  /* get cookie string */
  char*szRaw_cookie = (char*)apr_table_get( r->headers_in, "Cookie");
  if (!szRaw_cookie) return 0;

  /* loop to search cookie name in cookie header */
  do {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "Checking cookie %s, looking for %s", szRaw_cookie, szCookie_name);

    /* search cookie name in cookie string */
    if (!(szRaw_cookie = strstr(szRaw_cookie, szCookie_name))) return 0;
    szRaw_cookie_start=szRaw_cookie;
    /* search '=' */
    if (!(szRaw_cookie = strchr(szRaw_cookie, '='))) return 0;
  } while (strncmp(szCookie_name,szRaw_cookie_start,szRaw_cookie-szRaw_cookie_start)!=0);

  /* skip '=' */
  szRaw_cookie++;

  /* search end of cookie name value: ';' or end of cookie strings */
  if (!((szRaw_cookie_end = strchr(szRaw_cookie, ';')) || (szRaw_cookie_end = strchr(szRaw_cookie, '\0')))) return 0;

  /* dup the value string found in apache pool and set the result pool ptr to szCookie ptr */
  if (!(szCookie = apr_pstrndup(r->pool, szRaw_cookie, szRaw_cookie_end-szRaw_cookie))) return 0;
  /* unescape the value string */
  if (ap_unescape_url(szCookie) != 0) return 0;

  ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "finished cookie scan, returning %s", szCookie);

  return szCookie;
}

/* Check the cookie and make sure it is valid */
Cookie validateCookie(request_rec *r, const buffer_t *secret, const char *szCookieValue)
{

  /* split at | */
  char *iss = NULL;
  char *sig = NULL;
  char *crea = NULL;
  char *addr = apr_strtok((char *) szCookieValue, "|", &iss);
  if (!addr) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "malformed Persona cookie, can't extract email");
    return NULL;
  }

  iss = apr_strtok((char *) iss, "|", &crea);
  if (!iss) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "malformed Persona cookie, can't extract issuer");
    return NULL;
  }

  crea = apr_strtok((char *) crea, "|", &sig);
  if (!crea) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "malformed Persona cookie, can't extract time");
    return NULL;
  }

  Cookie c = apr_pcalloc(r->pool, sizeof(struct _Cookie));
  c->verifiedEmail = addr;
  c->identityIssuer = iss;
  c->created = strtol(crea, NULL, 10);

  char *digest64 = generateHMAC(r, secret, c);
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "Got cookie: email is %s; expected digest is %s; got digest %s",
                addr, digest64, sig);

  /* paranoia indicates that we should use a time-invariant compare here */
  if (strcmp(digest64, sig)) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "invalid Persona cookie");
    return NULL;
  }

  return c;
}

/** Create a session cookie with a given identity */
void sendSignedCookie(request_rec *r, const buffer_t *secret, const Cookie cookie)
{
  char *digest64 = generateHMAC(r, secret, cookie);
  /* syntax of cookie is identity|issuer|timestamp|signature */
  apr_table_set(r->err_headers_out, "Set-Cookie",
                apr_psprintf(r->pool, "%s=%s|%s|%" APR_TIME_T_FMT "|%s; Path=/",
                             PERSONA_COOKIE_NAME, cookie->verifiedEmail,
                             cookie->identityIssuer, cookie->created, digest64));
}

void sendResetCookie(request_rec *r) {
  apr_table_set(r->err_headers_out, "Set-Cookie",
                apr_psprintf(r->pool, "%s=; Path=/; Expires=Thu, 01-Jan-1970 00:00:01 GMT",
                PERSONA_COOKIE_NAME));
}
