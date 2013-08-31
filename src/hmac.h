#ifndef __APRX_HMAC_H__
#define __APRX_HMAC_H__

#include <apr_strings.h>
#include <apr_sha1.h>
#include <apr_base64.h>

#define APRX_HMAC_DIGESTSIZE APR_SHA1_DIGESTSIZE

apr_status_t aprx_hmac(const void *key, apr_size_t keylen, const char *data, apr_size_t datalen, void *result);

#endif
