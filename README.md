Copyright 2012 Andrei Sambra - andrei@fcns.eu


# What is WebIDauth? 

WebIDauth is a "full" authentication service (or Identification Provider) for [WebID](http://www.w3.org/wiki/WebID) enabled [FOAF](www.foaf-project.org/) profiles, aiming to provide a service similar to [foafssl.org](https://foafssl.org/srv/idp).

# Functionalities

Right now, WebIDauth supports the following functionalities:

* initiates the WebID protocol, by requesting an SSL client from connecting clients
* checks the request for a variable called **verbose** and verifies if it is set, and if so it displays the contents of the certificate used to connect to the IdP (the request does not have to contain a valid **authreqissuer** value)
* checks if the SubjectAltName filed contains something else other than the webid uri, and only processes the URI
* checks if the webid profile contains multiple public keys and cycles through them looking for a match

# Demo

One may check the demo available at https://my-profile.eu/ for instance (which uses [WebIDDelegatedAuth](https://github.com/WebIDauth/WebIDDelegatedAuth) to consume WebID and which relies on https://auth.my-profile.eu/, the Identification Provider running WebIDauth.

# How it works

To take an example, the web application at http://sp.example.com/ (which could be called Service Provider or SP) could have a "Login" link on their main page to allow users to authenticate using their webids (check http://auth.my-profile.eu/ for an example of such a demo SP).  This link points to a server which is running WebIDauth, let's say https://idp.example.com/, and which we will call IdP (Identification Provider) from now on (check https://auth.my-profile.eu/ for a real IdP). A typical link would look something like this:

`https://auth.my-profile.eu/auth/index.php?authreqissuer=https://sp.example.com/index.php`


What happens next is the IdP will demand an SSL certificate from the user's browser. From the certificate it will extract the webid URI, then after fetching the FOAF profile located at that specific URI it will attempt to match the public key of the certificate with the data found in the FOAF profile. Of course, additional verification steps take place during this process.

If the two match, it will then redirect the user back to the page contained in the **authreqissuer** variable (the Service at http://sp.example.com/), appending several variables. For client compatibility reasons, the variable names are the same with those returbed by foafssl.org, hence the new URL will look like this: 

**$authreqissuer?webid=$webid&ts=$timeStamp**&sig=$URLSignature&referer=$referer

Where the above variables have the following meanings:

* `$authreqissuer` is the URL passed by the server in the initial request (https://sp.example.com/index.php in the example).
* `$webid` is the WebID of the user connecting (the URL of the user's FOAF profile).
* `$timeStamp` is a time stamp in XML Schema format. This timestamp protects against replay attacks.
* `$URLSignature` is the signature of the whole URL in bold above (signed with the IdP's private SSL key).
* `$referer` is the address of the IdP, which might be needed to fetch the public key of the IdP's SSL certificate (in this example idp.example.com)

# Error responses

In case of error the service gets redirected to the following URL: **$authreqissuer?error=$code**

Where $code can be either one of:

* `nocert:` No certificates installed in the client's browser.
* `certExpired:` The certificate has expired
* `noVerifiedWebId:` WebId does not match the certificate.
* `noWebId:` No identity found for existing WebID.
* `IdPError:` Other error(s) in the IdP setup. Please warn the IdP administrator.

# Dependencies

PHP, OpenSSL, Apache's mod_ssl

It currently uses Graphite (http://graphite.ecs.soton.ac.uk/) and ARC2 (https://github.com/semsol/arc2/) PHP libraries for RDF parsing.

It requires a dedicated Web server whose SSL configuration can be adjusted so that it will initiate the SSL cert request to the connecting clients (see instructions in the example dot.htaccess provided).
Note that this may require a global configuration for Web servers like Apache, which will prevent hosting other Web apps on the same server if they don't need WebID authentication to be enabled full time. 

# Install

1. Simply copy the all the contents to your public web directory.
2. Rename the dot.htaccess file to .htaccess (or adjust your web server's config in a similar way)
3. Make sure Apache's mod_ssl is enabled on your webserver.
4. Edit file 'index.php' and replace the $server_key variable to use your server's private key. You may also change the temporary directory to some other location than the default one.
5. Save everything and start authenticating users by having them click a link similar to this one:
https:///index.php?authreqissuer=

You may test the resulting authentications with [libAuthentication](https://github.com/melvincarvalho/libAuthentication) or its "lite" sister lib [WebIDDelegatedAuth](https://github.com/WebIDauth/WebIDDelegatedAuth), in PHP applications.

# License

MIT License

# TODO

* test different formats of webid profiles

