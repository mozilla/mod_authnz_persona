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

#ifndef __DEFINES_H__
#define __DEFINES_H__

#include <stddef.h>

#define PERSONA_DEFAULT_VERIFIER_URL "https://verifier.login.persona.org/verify"
#define PERSONA_COOKIE_NAME "Persona"
#define PERSONA_ISSUER_NOTE "persona-identity-issuer"
#define PERSONA_SECRET_SIZE 1024
#define PERSONA_ASSERTION_HEADER "Persona-Assertion"
#define PERSONA_END_PAGE "\n</script>\n</html>\n"

#define ERRTAG "authnz_persona: "
#define VERSION "1.0.0"

typedef struct buffer {
  size_t len;
  char *data;
} buffer_t;

typedef struct persona_config {
  buffer_t *secret;
  buffer_t *logout_path;
} persona_config_t;

#endif
