#ifndef __CONFIG_H__
#define __CONFIG_H__

/* config structure */
typedef struct {
  char *cookieName;
  int 	authoritative;
  int 	authBasicFix;
  char  *forwardedRequestHeader;
  char *submitPath;
  char *logoutPath;
  char *verificationServerURL;
  int   verifyLocally;
  char *serverSecret;
} BrowserIDConfigRec;

#endif
