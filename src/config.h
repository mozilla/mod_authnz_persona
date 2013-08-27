#ifndef __CONFIG_H__
#define __CONFIG_H__

/* config structure */
typedef struct {
  char *cookieName;
  char  *forwardedRequestHeader;
  char *verificationServerURL;
  int   verifyLocally;
  char *serverSecret;
} BrowserIDConfigRec;

#endif
