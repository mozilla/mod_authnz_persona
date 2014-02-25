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
 *  Cookie management routines
 */

#ifndef __COOKIE_H__
#define __COOKIE_H__

#include <httpd.h>
#include "defines.h"

typedef struct _Cookie {
  const char *verifiedEmail; // email that was verified
  const char *identityIssuer; // domain that issued the identity
  apr_time_t created; // when this cookie was created
}* Cookie;

/* Look through the 'Cookie' headers for the indicated cookie; extract it
 * and URL-unescape it. Return the cookie on success, NULL on failure. */
char * extractCookie(request_rec *r, const buffer_t *secret, const char *szCookie_name);

/* Check the cookie and make sure it is valid */
Cookie validateCookie(request_rec *r, const buffer_t *secret, const char *szCookieValue);

/** Create a session cookie with a given identity */
void sendSignedCookie(request_rec *r, const buffer_t *secret, const Cookie cookie);

/* Send an empty cookie, to reset the session */
void sendResetCookie(request_rec *r);

#endif
