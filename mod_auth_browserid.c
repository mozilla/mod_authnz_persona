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


/*
SHA-1 in C
By Steve Reid <steve@edmweb.com>
100% Public Domain
*/

typedef struct {
    u_int32_t state[5];
    u_int32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;

void SHA1Transform(u_int32_t state[5], const unsigned char buffer[64]);
void SHA1Init(SHA1_CTX* context);
void SHA1Update(SHA1_CTX* context, const unsigned char* data, u_int32_t len);
void SHA1Final(unsigned char digest[20], SHA1_CTX* context);


/* ================ sha1.c ================ */
/* #define LITTLE_ENDIAN * This should be #define'd already, if true. */
/* #define SHA1HANDSOFF * Copies data before messing with it. */

#define SHA1HANDSOFF

#include <stdio.h>
#include <string.h>
#include <sys/types.h>	/* for u_int*_t */
#include <endian.h>

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#if BYTE_ORDER == LITTLE_ENDIAN
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) \
    |(rol(block->l[i],8)&0x00FF00FF))
#elif BYTE_ORDER == BIG_ENDIAN
#define blk0(i) block->l[i]
#else
#error "Endianness not defined!"
#endif
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);


/* Hash a single 512-bit block. This is the core of the algorithm. */

void SHA1Transform(u_int32_t state[5], const unsigned char buffer[64])
{
u_int32_t a, b, c, d, e;
typedef union {
    unsigned char c[64];
    u_int32_t l[16];
} CHAR64LONG16;
#ifdef SHA1HANDSOFF
CHAR64LONG16 block[1];  /* use array to appear as a pointer */
    memcpy(block, buffer, 64);
#else
    /* The following had better never be used because it causes the
     * pointer-to-const buffer to be cast into a pointer to non-const.
     * And the result is written through.  I threw a "const" in, hoping
     * this will cause a diagnostic.
     */
CHAR64LONG16* block = (const CHAR64LONG16*)buffer;
#endif
    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
    R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
    R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
    R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
    R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    /* Wipe variables */
    a = b = c = d = e = 0;
#ifdef SHA1HANDSOFF
    memset(block, '\0', sizeof(block));
#endif
}


/* SHA1Init - Initialize new context */

void SHA1Init(SHA1_CTX* context)
{
    /* SHA1 initialization constants */
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}


/* Run your data through this. */

void SHA1Update(SHA1_CTX* context, const unsigned char* data, u_int32_t len)
{
u_int32_t i;
u_int32_t j;

    j = context->count[0];
    if ((context->count[0] += len << 3) < j)
	context->count[1]++;
    context->count[1] += (len>>29);
    j = (j >> 3) & 63;
    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64-j));
        SHA1Transform(context->state, context->buffer);
        for ( ; i + 63 < len; i += 64) {
            SHA1Transform(context->state, &data[i]);
        }
        j = 0;
    }
    else i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}


/* Add padding and return the message digest. */

void SHA1Final(unsigned char digest[20], SHA1_CTX* context)
{
unsigned i;
unsigned char finalcount[8];
unsigned char c;

#if 0	/* untested "improvement" by DHR */
    /* Convert context->count to a sequence of bytes
     * in finalcount.  Second element first, but
     * big-endian order within element.
     * But we do it all backwards.
     */
    unsigned char *fcp = &finalcount[8];

    for (i = 0; i < 2; i++)
    {
	u_int32_t t = context->count[i];
	int j;

	for (j = 0; j < 4; t >>= 8, j++)
	    *--fcp = (unsigned char) t
    }
#else
    for (i = 0; i < 8; i++) {
        finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)]
         >> ((3-(i & 3)) * 8) ) & 255);  /* Endian independent */
    }
#endif
    c = 0200;
    SHA1Update(context, &c, 1);
    while ((context->count[0] & 504) != 448) {
	c = 0000;
        SHA1Update(context, &c, 1);
    }
    SHA1Update(context, finalcount, 8);  /* Should cause a SHA1Transform() */
    for (i = 0; i < 20; i++) {
        digest[i] = (unsigned char)
         ((context->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
    }
    /* Wipe variables */
    memset(context, '\0', sizeof(*context));
    memset(&finalcount, '\0', sizeof(finalcount));
}
/* ================ end of sha1.c ================ */


#define ERRTAG "Auth_browserID: "
#define VERSION "1.0.0"
#define unless(c) if(!(c))

/* apache module name */
module AP_MODULE_DECLARE_DATA mod_auth_browserid_module;

/* config structure */
typedef struct {

  int 	nAuth_browserid_SetSessionHTTPHeader;
  int 	nAuth_browserid_SetSessionHTTPHeaderEncode;

  char *	szAuth_browserid_CookieName;
  int 	nAuth_browserid_Authoritative;

  int 	nAuth_browserid_authbasicfix;

  char *        szAuth_browserid_SubmitPath;
  char *        szAuth_browserid_VerificationServerURL;
  int        szAuth_browserid_VerifyLocally;

  char *        szAuth_browserid_Secret;
} strAuth_browserid_config_rec;

/* Look through 'Cookie' header for indicated cookie; extract it
 * and URL-unescape it. Return the cookie on success, NULL on failure. */
static char * extract_cookie(request_rec *r, const char *szCookie_name) 
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
    const char *rpw, *w;
    
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

     ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "fixing apache Authorization header for this request using user:%s",r->user);

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

/* Check the cookie and make sure it is valid */
static int Auth_browserID_validateCookie(request_rec *r, strAuth_browserid_config_rec *conf, char *szCookieValue)
{
    /* split at | */
    char *sig = NULL;
    char *addr = apr_strtok(szCookieValue, "|", &sig);
    if (!addr) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "malformed BrowserID cookie");
      return 1;
    }

    /* Validate the signature */
    SHA1_CTX context;
    SHA1Init(&context);
    SHA1Update(&context, (unsigned char*)addr, strlen(addr));
    SHA1Update(&context, (unsigned char*)conf->szAuth_browserid_Secret, strlen(conf->szAuth_browserid_Secret));
    unsigned char digest[20];
    SHA1Final(digest, &context);
    
    char *digest64 = apr_palloc(r->pool, apr_base64_encode_len(20));
    apr_base64_encode(digest64, (char*)digest, 20);

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

/* check if szGroup are in szGroups. */
static int get_Auth_browserid_grp(request_rec *r, char *szGroup, char *szGroups)
{
    char *szGrp_End;
    char *szGrp_Pos;
    char *szMyGroups;

    /* make a copy */
    szMyGroups=apr_pstrdup(r->pool,szGroups);
    /* search group in groups */
    unless(szGrp_Pos=strstr(szMyGroups,szGroup)) {
      return DECLINED;
    }
    /* search the next ':' and set '\0' in place of ':' */
    if ((szGrp_End=strchr(szGrp_Pos,':'))) szGrp_End[0]='\0';

    /* compar szGroup with szGrp_Pos if ok return ok */
    if(strcmp(szGroup,szGrp_Pos))
       return DECLINED;
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "group found=%s",szGrp_Pos);
    return OK;
}

/**************************************************
 * Authentication phase
 *
 * Pull the cookie from the header and verify it.
 **************************************************/
static int Auth_browserid_check_cookie(request_rec *r)
{
    strAuth_browserid_config_rec *conf=NULL;
    char *szCookieValue=NULL;
    apr_table_t *pAuthSession=NULL;
    apr_status_t tRetStatus;
    char *szRemoteIP=NULL;

    ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,ERRTAG  "ap_hook_check_user_id in - Auth_browserid_check_cookie");

    /* get apache config */
    conf = ap_get_module_config(r->per_dir_config, &mod_auth_browserid_module);

    unless(conf->nAuth_browserid_Authoritative)
	   return DECLINED;

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "AuthType are '%s'", ap_auth_type(r));
    unless(strncmp("BrowserID",ap_auth_type(r),9)==0) {
	   ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Auth type must be 'BrowserID'");
      return HTTP_UNAUTHORIZED;
    }

    unless(conf->szAuth_browserid_CookieName) {
      ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "No Auth_browserid_CookieName specified");
      return HTTP_UNAUTHORIZED;
    }

    /* get cookie who are named szAuth_browserid_CookieName */
    unless(szCookieValue = extract_cookie(r, conf->szAuth_browserid_CookieName))
    {
      ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, ERRTAG "BrowserID cookie not found; not authorized! RemoteIP:%s",szRemoteIP);
      return HTTP_UNAUTHORIZED;
    }
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "got cookie; value is %s", szCookieValue);

    /* Check cookie validity */
    if (Auth_browserID_validateCookie(r, conf, szCookieValue)) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r, ERRTAG "Invalid BrowserID cookie: %s", szCookieValue, r->filename);
        return HTTP_UNAUTHORIZED;
    }

    /* set REMOTE_USER var for scripts language */
    apr_table_setn(r->subprocess_env,"REMOTE_USER",r->user);

    /* log authorisation ok */
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "BrowserID authentication ok");

    /* fix http header for php */
    /*    if (conf->nAuth_browserid_authbasicfix) fix_headers_in(r,(char*)apr_table_get(pAuthSession,"Password"));*/

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
    strAuth_browserid_config_rec *conf=NULL;
    char *szMyUser=r->user;
    char *szUser;
    int m = r->method_number;

    const apr_array_header_t *reqs_arr=NULL;
    require_line *reqs=NULL;

    register int x;
    const char *szRequireLine;
    const char *szFileName;
    char *szRequire_cmd;
    apr_status_t tRetStatus;

    ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,ERRTAG  "ap_hook_auth_checker in");

    /* get apache config */
    conf = ap_get_module_config(r->per_dir_config, &mod_auth_browserid_module);

    /* check if this module is authoritative */
    unless(conf->nAuth_browserid_Authoritative)
      return DECLINED;

    /* get require line */
    reqs_arr = ap_requires(r);
    reqs = reqs_arr ? (require_line *) reqs_arr->elts : NULL;

    /* decline if no require line found */
    if (!reqs_arr) return DECLINED;

    /* walk through the array to check each require command */
    for (x = 0; x < reqs_arr->nelts; x++) {

      if (!(reqs[x].method_mask & (AP_METHOD_BIT << m)))
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
      if (strcmp(szMyUser, szUser)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r ,ERRTAG  "user '%s' is not the required user '%s'",szMyUser,szUser);
        return HTTP_FORBIDDEN;
      }
      ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r ,ERRTAG  "user '%s' is authorized",szMyUser);
      return OK;
    }
    /* check for users in a file */ 
    else if (!strcmp("userfile",szRequire_cmd)) {
      szFileName = ap_getword_conf(r->pool, &szRequireLine);
      if (!user_in_file(r, szMyUser, szFileName)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r ,ERRTAG  "user '%s' is not in username list at '%s'",szMyUser,szFileName);
        return HTTP_FORBIDDEN;
	     } else {
        return OK;
      }
    }
  }

  ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r ,ERRTAG  "user '%s' is not authorized",szMyUser);
  /* forbid by default */
  return HTTP_FORBIDDEN;
}



struct MemoryStruct {
  char *memory;
  size_t size;
  size_t realsize;
  request_rec *r;
};
 
 
static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
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

static char *verifyAssertionRemote(request_rec *r, strAuth_browserid_config_rec *conf, char *assertionText)
{
  CURL *curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_URL, conf->szAuth_browserid_VerificationServerURL);
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

void createSessionCookie(request_rec *r, strAuth_browserid_config_rec *conf, char *identity)
{
  /*** XXX salt the secret ***/
  SHA1_CTX context;
  SHA1Init(&context);
  SHA1Update(&context, (unsigned char*)identity, strlen(identity));
  SHA1Update(&context, (unsigned char*)conf->szAuth_browserid_Secret, strlen(conf->szAuth_browserid_Secret));
  
  unsigned char digest[20];
  SHA1Final(digest, &context);
  char *digest64 = apr_palloc(r->pool, apr_base64_encode_len(20));
  apr_base64_encode(digest64, (char*)digest, 20);
  
  /* set a new cookie containing the assertion*/
  apr_table_set(r->err_headers_out, "Set-Cookie", 
    apr_psprintf(r->pool, "%s=%s|%s; Path=/", 
      conf->szAuth_browserid_CookieName, identity, digest64));
}

/*
 * This routine is called after the request has been read but before any other
 * phases have been processed.  This allows us to make decisions based upon
 * the input header fields.
 *
 * The return value is OK, DECLINED, or HTTP_mumble.  If we return OK, no
 * further modules are called for this phase.
 */
static int Auth_browserid_fixups(request_rec *r)
{
    strAuth_browserid_config_rec *conf=NULL;

    /* get apache config */
    conf = ap_get_module_config(r->per_dir_config, &mod_auth_browserid_module);

    if (conf->szAuth_browserid_SubmitPath && !strcmp(r->uri, conf->szAuth_browserid_SubmitPath)) {
      /* this is a login submission */
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

          /* verify the assertion... */
          yajl_val parsed_result = NULL;
          if (conf->szAuth_browserid_VerificationServerURL) {
            char *assertionResult = verifyAssertionRemote(r, conf, (char*)assertionParsed);
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
          } else {
            if (conf->szAuth_browserid_VerifyLocally) {
              char *hdr=NULL, *payload=NULL, *sig=NULL;
              char *assertion = apr_pstrdup(r->pool, assertionParsed);
              hdr= apr_strtok(assertion, ".", &payload);
              if (hdr) {
                payload= apr_strtok(payload, ".", &sig);
                if (sig) {
                  int len = apr_base64_decode_len(payload);
                  char *payloadDecode = apr_pcalloc(r->pool, len+1);
                  int decodeLen = apr_base64_decode(payloadDecode, payload);
                  
                  char errorBuffer[256];
                  parsed_result = yajl_tree_parse(payloadDecode, errorBuffer, 255);
                  if (!parsed_result) {
                    ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,ERRTAG "Error parsing BrowserID login: malformed payload: %s", errorBuffer);
                    return DECLINED;
                  }
                  /** XXX more local validation required!!! Check timestamp, audience **/
                }
              }
            } else {
              ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,ERRTAG "Cannot verify BrowserID login: no verification server configured!");
              return DECLINED;
            }
          }
          if (parsed_result) {
            char *parsePath[2];
            parsePath[0] = "email";
            parsePath[1] = NULL;
            yajl_val foundEmail = yajl_tree_get(parsed_result, (const char**)parsePath, yajl_t_any);
            if (!foundEmail || foundEmail->type != yajl_t_string) {
              ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,ERRTAG "Error parsing BrowserID login: no email in payload");
              return DECLINED;
            }
            ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG "In post_read_request; got email %s", foundEmail->u.string);
            
            createSessionCookie(r, conf, foundEmail->u.string);

            /* redirect to the requested resource */
            apr_table_set(r->headers_out,"Location", returnto);
            
            return HTTP_TEMPORARY_REDIRECT;
          } 
        }
      } else {
	     ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,ERRTAG "In post_read_request; this is a POST - skipping it for now");
      }
    }
    /* otherwise we don't care */
    return DECLINED;
}


/**************************************************
 * register module hooks
 **************************************************/
static void register_hooks(apr_pool_t *p)
{
    ap_hook_check_user_id(Auth_browserid_check_cookie, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_auth_checker(Auth_browserid_check_auth, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_fixups(Auth_browserid_fixups, NULL, NULL, APR_HOOK_FIRST);
}

/************************************************************************************
 *  Apache CONFIG Phase:
 ************************************************************************************/
static void *create_Auth_browserid_dir_config(apr_pool_t *p, char *d)
{
    strAuth_browserid_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->szAuth_browserid_CookieName = apr_pstrdup(p,"BrowserID");
    conf->szAuth_browserid_SubmitPath = "/mod_browserid_submit";
    conf->szAuth_browserid_Secret = "BrowserIDSecret";
    conf->nAuth_browserid_Authoritative = 0;  /* not by default */
    conf->nAuth_browserid_authbasicfix = 1;  /* fix header for php auth by default */
    conf->nAuth_browserid_SetSessionHTTPHeader = 0; /* set session information in http header of authenticated user */
    conf->nAuth_browserid_SetSessionHTTPHeaderEncode = 1; /* encode http header groups value by default */


    return conf;
}

/* apache config fonction of the module */
static const command_rec Auth_browserid_cmds[] =
{
    AP_INIT_FLAG ("AuthBrowserIDSetSessionHTTPHeader", ap_set_flag_slot,
     (void *)APR_OFFSETOF(strAuth_browserid_config_rec, nAuth_browserid_SetSessionHTTPHeader),
     OR_AUTHCFG, "Set to 'yes' to set session information to http header of the authenticated users, no by default"),

    AP_INIT_FLAG ("AuthBrowserIDSetSessionHTTPHeaderEncode", ap_set_flag_slot,
     (void *)APR_OFFSETOF(strAuth_browserid_config_rec, nAuth_browserid_SetSessionHTTPHeaderEncode),
     OR_AUTHCFG, "Set to 'yes' to mime64 encode session information to http header, no by default"),

    AP_INIT_TAKE1("AuthBrowserIDCookieName", ap_set_string_slot,
     (void *)APR_OFFSETOF(strAuth_browserid_config_rec, szAuth_browserid_CookieName),
     OR_AUTHCFG, "Name of cookie to set"),

    AP_INIT_FLAG ("AuthBrowserIDAuthoritative", ap_set_flag_slot,
     (void *)APR_OFFSETOF(strAuth_browserid_config_rec, nAuth_browserid_Authoritative),
     OR_AUTHCFG, "Set to 'yes' to allow access control to be passed along to lower modules, set to 'no' by default"),

    AP_INIT_FLAG ("AuthBrowserIDSimulateAuthBasic", ap_set_flag_slot,
     (void *)APR_OFFSETOF(strAuth_browserid_config_rec, nAuth_browserid_authbasicfix),
     OR_AUTHCFG, "Set to 'no' to fix http header and auth_type for simulating auth basic for scripting language like php auth framework work, set to 'yes' by default"),

    AP_INIT_TAKE1 ("AuthBrowserIDSubmitPath", ap_set_string_slot,
     (void *)APR_OFFSETOF(strAuth_browserid_config_rec, szAuth_browserid_SubmitPath),
     OR_AUTHCFG, "Path to which login forms will be submitted.  Form must contain a field named 'assertion'"),

    AP_INIT_TAKE1 ("AuthBrowserIDVerificationServerURL", ap_set_string_slot,
     (void *)APR_OFFSETOF(strAuth_browserid_config_rec, szAuth_browserid_VerificationServerURL),
     OR_AUTHCFG, "URL of the BrowserID verification server."),

    AP_INIT_FLAG ("AuthBrowserIDVerifyLocally", ap_set_flag_slot,
     (void *)APR_OFFSETOF(strAuth_browserid_config_rec, szAuth_browserid_VerifyLocally),
     OR_AUTHCFG, "Set to 'yes' to verify assertions locally; ignored if VerificationServerURL is set"),

    AP_INIT_TAKE1 ("AuthBrowserIDSecret", ap_set_string_slot,
     (void *)APR_OFFSETOF(strAuth_browserid_config_rec, szAuth_browserid_Secret),
     OR_AUTHCFG, "Server secret for authentication cookie."),

    {NULL}
};

/* apache module structure */
module AP_MODULE_DECLARE_DATA mod_auth_browserid_module =
{
    STANDARD20_MODULE_STUFF,
    create_Auth_browserid_dir_config, /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    Auth_browserid_cmds,              /* command apr_table_t */
    register_hooks              /* register hooks */
};
