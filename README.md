mod_browserid is a module for Apache 2.0 or later that implements Apache authentication for the BrowserID protocol.

== Building and Installing ==

git clone git@github.com:mozilla/mod_browserid.git
cd mod_browserid
make
sudo make install

(this assumes apxs is behaving properly on your system)

== Dependencies ==

* apache 2.0 or later
* libcurl 7.10.8 or later
* yajl 2.0 or later

== Design Discussion ==

The nodule works by intercepting requests bound for protected resources, and checking for the presence of a session cookie.  The name of the cookie is defined in the module's configuration.  Note that while the configuration seems to allow you to set a different cookie name for each protected location, the actual cookie is set for the root of the virtual host, so all Location and Directory directives within a host MUST have the same cookie name.

If the cookie is not found, the user agent is served the ErrorDocument for the directory instead of the resource, with an error code of 401 (which prevents browser caching).  The ErrorDocument must implement the BrowserID sign-in flow, and submit the result to the path identified by the `AuthBrowserIDSubmitPath` directive.  (XXX Note that POST parsing isn't implemented yet; you must use GET!)  The form submission must contain a value named `assertion`, containing the assertion, and another named `returnto`, containing the relative path of the originally requested resource.

The module will intercept requests bound for the SubmitPath, and will verify the BrowserID assertion by submitting it to the server identified in the `AuthBrowserIDVerificationServerURL` directive. (XXX no way to configure SSL trust chain yet).  Note that the `ServerName` directive of the server containing the protected directory MUST match the hostname the client uses to perform the login, so the Audience field of the BrowserID assertion checks out.  

If the assertion is verified, the module generates a signed cookie containing the user's email address.  The `AuthBrowserIDSecret` directive MUST be used to provide a unique per-server key, or this step is not secure.  All secret values for a host must be identical, since only one cookie is generated.  (XX Note that there is NO LOGOUT and NO EXPIRY on this cookie yet.  It's not done!)  There is currently no option to encrypt the cookie, so the user's email address is visible in plaintext in the cookie; until encryption is implemented, the only privacy-protecting deployment is to use SSL.  (See issue XX)

Once the session cookie has been established, the "require" directive can be used to specify a single user or a list of users. (XXX could be cool to implement globbing or other ways of identifying a set of valid users, e.g. *@host.com)

The identity thus verified can be passed on to CGI scripts or downstream webservers; the REMOTE_USER environment variable is automatically set to the verified identity, and an HTTP header containing the identity can be set with the `AuthBrowserIDSetSessionHTTPHeader` directive (XX not implemented yet).

== Apache Directives ==

AuthBrowserIDCookieName:
	Name of cookie to set

AuthBrowserIDSubmitPath:
	Path to which login forms will be submitted.  Form must contain a fields named 'assertion' and 'returnto'.

AuthBrowserIDVerificationServerURL:
	URL of the BrowserID verification server.

AuthBrowserIDSecret:
	Server secret for authentication cookie.

AuthBrowserIDVerifyLocally:
	Set to 'yes' to verify assertions locally; ignored if VerificationServerURL is set

omce authentication is set up, the "require" directive can be used with one of these values:

require valid-user: a valid BrowserID identity must have been presented
require user <someID>: a specific identity must be presented
require userfile <path-to-file>: the BrowserID presented by the user must be in this newline-separated list of identities

* NOT YET IMPLEMENTED: *
AuthBrowserIDSetSessionHTTPHeader: 
	Set to 'yes' to set session information to http header of the authenticated users, no by default

AuthBrowserIDAuthoritative:
	Set to 'yes' to allow access control to be passed along to lower modules, set to 'no' by default

AuthBrowserIDSimulateAuthBasic:
	Set to 'no' to fix http header and auth_type for simulating auth basic for scripting language like php auth framework work, set to 'yes' by default


== Sample Configuration ==

httpd.conf:

  LoadModule mod_authBrowserIDmodule modules/mod_auth_browserid.so

  <Directory /usr/local/apache2/htdocs/id_login >
  AuthBrowserIDCookieName myauthcookie
  AuthBrowserIDSubmitPath "/id_login/submit"
  AuthBrowserIDVerificationServerURL "https://browserid.org/verify"
  </Directory>
  
  <Directory /usr/local/apache2/htdocs/id_demo/ >
   AuthType BrowserID
   AuthBrowserIDAuthoritative on
   AuthBrowserIDCookieName myauthcookie
   AuthBrowserIDVerificationServerURL "https://browserid.org/verify"
  
   # must be set (apache mandatory) but not used by the module
   AuthName "My Login"
  
   # to redirect unauthorized users to the login page
   ErrorDocument 401 "/id_login/browserid_login.php"

   require userfile /usr/local/apache2/htdocs/id_demo_users
  </Directory>

/id_login/browserid_login.php:

  <?php?><html>
  <head>
  <script src="https://browserid.org/include.js" type="text/javascript"></script>
  <title>Authentication</title>
  </head>
  <body style="margin-top:60px">
  <center>To view that file, please<br>
  <a href="#" onclick="doLogin()"><img src="/sign_in_blue.png"></a></center>
  <form method="GET" action="/id_login/submit" id="loginform">
  <input type="hidden" name="assertion" id="assertion">
  <input type="hidden" name="returnto" id="returnto" 
     value="<?php if (isset($_SERVER["REDIRECT_URL"])) echo $_SERVER["REDIRECT_URL"]; else echo "/"; ?>">
  </form>
  <script>
  function doLogin()
  {
        navigator.id.getVerifiedEmail(function(assertion) {
                document.getElementById("assertion").value = assertion;
                document.getElementById("loginform").submit();
        });
  }
  </script></body></html>

/usr/local/apache2/htdocs/id_demo_users:

  user@site.com
  otheruser@site.com
