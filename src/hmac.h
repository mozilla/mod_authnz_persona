#ifndef __HMAC_H__
#define __HMAC_H__

#include <apr_strings.h>
#include <apr_sha1.h>
#include <apr_base64.h>

#define HMAC_DIGESTSIZE APR_SHA1_DIGESTSIZE

void hmac(const void *key, apr_size_t keylen, const char *data, apr_size_t datalen, void *result);

#endif
