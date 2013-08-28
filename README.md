mod_authn_persona is a module for Apache 2.0 or later that
allows you quickly add Persona Authentication to a site hosted with
apache.

Installation
=======================

```
git clone https://github.com/lloyd/mod_authn_persona.git
cd mod_authn_persona
make
sudo make install
```

(this assumes apxs is behaving properly on your system; set the
APXS_PATH variable to your apxs or apxs2 as appropriate)

# Configuration

Configure the module:

    LoadModule authn_persona_module modules/authn_persona_module.so

    <Location />
       AuthType Persona
       require valid-user # XXX: figure out how this should work
    </Location>

This will cause the module to require Persona authentication for all
requests to the server.

Dependencies
============

* apache 2.0 or later
* libcurl 7.10.8 or later
* yajl 2.0 or later

# Features

* **zero configuration** - The module is designed with reasonable
    defaults, so you can simply drop it in
* **automatic re-auth** - The module is designed to use session
    cookies and automatically re-authenticate.

# How it Works

The module works by intercepting requests bound for protected
resources, and checking for the presence of a session cookie.

If the cookie is not found, the user agent is served an HTML document
that presents a Persona login page.

Upon successful authentication with Persona, this page will send a
request to the server with a Persona assertion in an HTTP header.  The
module, upon detecting no cookie is present, will look for this
header, validate the assertion, and set a short session cookie.

The authentication page will then reload the desired resource.

Available Configuration
=================

* (not yet implemented) `AuthnPersonaCookieSecret`:
	A secret that will be used to sign cookies.  If not provided, upon server
  start cookies will be generated automatically.  Given re-authentication
  is automatic, it is only required to set a cookie secret if your
  application is hosted on multiple load balanced apache servers.

(not yet implemented) A way to specifiy the IdP you require
