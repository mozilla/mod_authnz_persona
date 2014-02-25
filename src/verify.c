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

#include <stddef.h>
#include <string.h>

#include "apr_strings.h"
#include "apr_pools.h"

#include "httpd.h"
#include "http_log.h"

#include <yajl/yajl_tree.h>
#include <curl/curl.h>
#include <curl/easy.h>

#include "defines.h"
#include "verify.h"

/* Helper struct for CURL response */
struct MemoryStruct {
  char *memory;
  size_t used;
  size_t allocated;
  request_rec *r;
};

static const char * jsonErrorResponse = "{\"status\":\"failure\", \"reason\": \"%s: %s\"}";


/** Callback function for streaming CURL response */
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t data_size = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  if (mem->used + data_size >= mem->allocated) {
    mem->allocated = mem->used + data_size + 256;
    void *tmp = apr_palloc(mem->r->pool, mem->allocated);
    memcpy(tmp, mem->memory, mem->used);
    mem->memory = tmp;
  }

  memcpy(&(mem->memory[mem->used]), contents, data_size);
  mem->used += data_size;
  mem->memory[mem->used] = 0;
  return data_size;
}

/* Pass the assertion to the verification service defined in the config,
 * and return the result to the caller */
static char *verifyAssertionRemote(request_rec *r, char *assertionText)
{
  CURL *curl = curl_easy_init();

  curl_easy_setopt(curl, CURLOPT_URL, PERSONA_DEFAULT_VERIFIER_URL);
  curl_easy_setopt(curl, CURLOPT_POST, 1);

  ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r,
                ERRTAG  "Requesting verification with audience %s", r->server->server_hostname);

  // XXX: audience should be an origin, see docs or issue mozilla/browserid#82
  char *body = apr_psprintf(r->pool, "assertion=%s&audience=%s",
                            assertionText, r->server->server_hostname);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
  /** XXX set certificate for SSL negotiation */

  struct MemoryStruct chunk;
  chunk.memory = apr_pcalloc(r->pool, 1024);
  chunk.used = 0;
  chunk.allocated = 1024;
  chunk.r = r;
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-mod_authnz_persona-agent/1.0");

  CURLcode result = curl_easy_perform(curl);
  if (result != 0) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r ,
                  ERRTAG  "Error while communicating with Persona verification server: %s",
                  curl_easy_strerror(result));
    curl_easy_cleanup(curl);
    return NULL;
  }
  long responseCode;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &responseCode);
  if (responseCode != 200) {
    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r ,
                  ERRTAG  "Error while communicating with Persona verification server: result code %ld", responseCode);
    curl_easy_cleanup(curl);
    return NULL;
  }
  curl_easy_cleanup(curl);
  return chunk.memory;
}

/*
 * process an assertion using the hosted verifier.
 *
 * TODO: local verification
 */
VerifyResult processAssertion(request_rec *r, const char *assertion)
{
  VerifyResult res = apr_pcalloc(r->pool, sizeof(struct _VerifyResult));
  yajl_val parsed_result = NULL;

  char *assertionResult = verifyAssertionRemote(r, (char*) assertion);

  if (assertionResult) {
    char errorBuffer[256];
    parsed_result = yajl_tree_parse(assertionResult, errorBuffer, 255);
    if (!parsed_result) {
      res->errorResponse = apr_psprintf(r->pool, jsonErrorResponse,
                                       "malformed payload", errorBuffer);
      return res;
    }
  } else {
    // XXX: verifyAssertionRemote should return specific error message.
    res->errorResponse = apr_psprintf(r->pool, jsonErrorResponse,
                                     "communication error", "can't contact verification server");
    return res;
  }

  char *parsePath[2];
  parsePath[0] = "email";
  parsePath[1] = NULL;
  yajl_val foundEmail = yajl_tree_get(parsed_result, (const char**)parsePath, yajl_t_string);

  if (!foundEmail) {
    res->errorResponse = apr_pstrdup(r->pool, assertionResult);
    return res;
  }

  parsePath[0] = "issuer";
  parsePath[1] = NULL;
  yajl_val identityIssuer = yajl_tree_get(parsed_result, (const char**)parsePath, yajl_t_string);

  if (!identityIssuer) {
    res->errorResponse = apr_pstrdup(r->pool, assertionResult);
    return res;
  }

  res->verifiedEmail = apr_pstrdup(r->pool, foundEmail->u.string);
  res->identityIssuer = apr_pstrdup(r->pool, identityIssuer->u.string);

  return res;
}
