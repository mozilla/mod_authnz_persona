#ifndef __DEFINES_H__
#define __DEFINES_H__

#include <stddef.h>

#define PERSONA_DEFAULT_VERIFIER_URL "https://verifier.login.persona.org/verify"
#define PERSONA_COOKIE_NAME "Persona"
#define PERSONA_SECRET_SIZE 1024

#define ERRTAG "Auth_browserID: "
#define VERSION "1.0.0"
#define unless(c) if(!(c))

typedef struct buffer {
  size_t len;
  char *data;
} buffer_t;

#endif
