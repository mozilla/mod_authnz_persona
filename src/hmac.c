#include "hmac.h"

#define APRX_HMAC_BLOCKSIZE 64

/* Somewhat arbitrary mask values, but they are straight from the spec */
#define APRX_HMAC_IPAD 0x36
#define APRX_HMAC_OPAD 0x5c

static void aprx_mxor(void *, const void *, apr_size_t);

/* Implements an HMAC with SHA1 the correct, safe way : http://en.wikipedia.org/wiki/Hash-based_message_authentication_code
 * 
 * Basic idea is to split the key in 2 parts, then hash the data twice, with 2 separate pieces of the key appended
 *
 * HMAC (K,m) = H((K+opad) | H((K+ipad) | m))
 *
 * Tricky, but much, much safer than the trivial implementation of HMAC(K,m) = H(K|m)
 *
 */

apr_status_t aprx_hmac(const void *key, apr_size_t keylen, const char *data, apr_size_t datalen, void *result) {

  apr_sha1_ctx_t inner;
  apr_sha1_ctx_t outer;
  unsigned char keypad[APRX_HMAC_BLOCKSIZE];
  unsigned char inner_digest[APR_SHA1_DIGESTSIZE];

  /* Shorten the key down to the blocksize, anything more is useless */
  if (keylen > APRX_HMAC_BLOCKSIZE) {
    apr_sha1_ctx_t context;
    unsigned char digest[APR_SHA1_DIGESTSIZE];
    apr_sha1_init(&context);
    apr_sha1_update_binary(&context, key, keylen);
    apr_sha1_final(digest, &context);
    key = digest;
    keylen = APR_SHA1_DIGESTSIZE;
  }

  /* Prepare and mask the inner portion of the key */
  memset(keypad, APRX_HMAC_IPAD, APRX_HMAC_BLOCKSIZE);
  aprx_mxor(keypad, key, keylen);

  /* Compute the inner hash */
  apr_sha1_init(&inner);
  apr_sha1_update_binary(&inner, keypad, APRX_HMAC_BLOCKSIZE);
  apr_sha1_update(&inner, data, datalen);
  apr_sha1_final(inner_digest, &inner);

  /* Prepare and mask the outer portion of the key */
  memset(keypad, APRX_HMAC_OPAD, APRX_HMAC_BLOCKSIZE);
  aprx_mxor(keypad, key, keylen);

  /* Compute the outer hash */
  apr_sha1_init(&outer);
  apr_sha1_update_binary(&outer, keypad, APRX_HMAC_BLOCKSIZE);
  apr_sha1_update_binary(&outer, inner_digest, APR_SHA1_DIGESTSIZE);
  apr_sha1_final(result, &outer);

  return APR_SUCCESS;

}

/* util to XOR src on top of dst */
static void aprx_mxor(void *dst, const void *src, apr_size_t len) {
    char const *s = src;
    char *d = dst;
    for (; len > 0; len--)
        *d++ ^= *s++;
    return;
}
