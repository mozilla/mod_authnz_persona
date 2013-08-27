#ifndef __CONFIG_H__
#define __CONFIG_H__

/* config structure */
typedef struct {
  char  *forwardedRequestHeader;
  int   verifyLocally;
  char *serverSecret;
} BrowserIDConfigRec;

#endif
