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

#ifndef __VERIFY_H__
#define __VERIFY_H__

#include "defines.h"
#include "cookie.h"
#include "config.h"
#include "verify.h"

#include <stdio.h>
#include <string.h>
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"
#include "apr_uuid.h"
#include "apr_tables.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"   /* for ap_hook_(check_user_id | auth_checker)*/
#include "apr_base64.h"
#include <yajl/yajl_tree.h>
#include <curl/curl.h>
#include <curl/easy.h>

/* Helper struct for CURL response */
struct MemoryStruct {
  char *memory;
  size_t size;
  size_t realsize;
  request_rec *r;
};

/** Callback function for streaming CURL response */
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  if (mem->size + realsize >= mem->realsize) {
    mem->realsize = mem->size + realsize + 256;
    void *tmp = apr_palloc(mem->r->pool, mem->size + realsize + 256);
    memcpy(tmp, mem->memory, mem->size);
    mem->memory = tmp;
  }

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
  return realsize;
}

/* Pass the assertion to the verification service defined in the config,
 * and return the result to the caller */
static char *verifyAssertionRemote(request_rec *r, BrowserIDConfigRec *conf, char *assertionText)
{
  CURL *curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_URL, conf->verificationServerURL);
  curl_easy_setopt(curl, CURLOPT_POST, 1);

  ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r ,
                ERRTAG  "Requeting verification with audience %s", r->server->server_hostname);

  char *body = apr_psprintf(r->pool, "assertion=%s&audience=%s", 
                            assertionText, r->server->server_hostname);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
  /** XXX set certificate for SSL negotiation */

  struct MemoryStruct chunk;
  chunk.memory = apr_pcalloc(r->pool, 1024);
  chunk.size = 0;
  chunk.realsize = 1024;
  chunk.r = r;
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-mod_browserid-agent/1.0");

  CURLcode result = curl_easy_perform(curl);
  if (result != 0) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r ,
                  ERRTAG  "Error while communicating with BrowserID verification server: %s",
                  curl_easy_strerror(result));
    curl_easy_cleanup(curl);
    return NULL;
  }
  long responseCode;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
  if (responseCode != 200) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r ,
                  ERRTAG  "Error while communicating with BrowserID verification server: result code %ld", responseCode);
    curl_easy_cleanup(curl);
    return NULL;
  }
  curl_easy_cleanup(curl);
  return chunk.memory;
}

/* Called from the fixup_handler when we receive a form submission.
 *
 * XXX handle POST submissions correctly - this will take some work,
 *     as we have to loop to handle chunked submissions
 */
int processAssertion(request_rec *r, BrowserIDConfigRec *conf, const char * assertion)
{
  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG "Submission to BrowserID form handler");

  /* verify the assertion... */
  yajl_val parsed_result = NULL;

  char *assertionResult = verifyAssertionRemote(r, conf, (char*) assertion);
  if (assertionResult) {
    char errorBuffer[256];
    parsed_result = yajl_tree_parse(assertionResult, errorBuffer, 255);
    if (!parsed_result) {
      ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,ERRTAG "Error parsing BrowserID verification response: malformed payload: %s", errorBuffer);
      return DECLINED;
    }
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG
                  "In post_read_request; parsed JSON from verification server: %s", assertionResult);
  } else {
    ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,ERRTAG
                  "Unable to verify assertion; communication error with verification server");
    return DECLINED;
  }

  if (parsed_result) {
    char *parsePath[2];
    parsePath[0] = "email";
    parsePath[1] = NULL;
    yajl_val foundEmail = yajl_tree_get(parsed_result, (const char**)parsePath, yajl_t_any);

    /** XXX if we don't have an email, something went wrong.  Should pull the error code properly!  This will
     *  probably require refactoring this function since the local path is different.  ***/
    if (!foundEmail || foundEmail->type != yajl_t_string) {
      ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,ERRTAG "Error parsing BrowserID login: no email in payload");
      return DECLINED;
    }
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG "In post_read_request; got email %s", foundEmail->u.string);
    createSessionCookie(r, conf, foundEmail->u.string);

    return OK;
  }

  return DECLINED;
}

#endif
