<?
/* -----------------------------------------------------------------------------
 * 
 * Filename   : WebIDauth.php
 * Date       : 11th July 2012
 * 
 * Version 0.3
 * 
 * Author: Andrei Sambra - andrei@fcns.eu
 * 
 * Copyright (C) 2012 Andrei Sambra
 * 
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * -----------------------------------------------------------------------------
 */

require_once('Graphite.php');
require_once('arc/ARC2.php');

/**
 * Implements WebID Authentication
 * seeAlso https://foafssl.org/srv/idp
 *
 * If successfull, it redirects the user to the Service Provider's URI
 * adding information like webid, timestamp (signing them with the IdP's
 * private key). 
 * Ex. for Service Provider http://auth.my-profile.eu it will return:
 * http://auth.my-profile.eu/index.php?webid=$webid&ts=$timeStamp&sig=$URLSignature
 */
class WebIDauth {
    public  $err        = array();  // will hold our errors for diagnostics
    private $webid      = array();  // webid URIs
    private $ts         = null;     // timestamp in W3C XML format
    private $cert       = null;     // php array with the contents of the certificate
    private $cert_pem   = null;     // certificate in pem format
    private $modulus    = null;     // modulus component of the public key
    private $exponent   = null;     // exponent component of the public key
    private $is_bnode   = false;    // if the modulus is expressed as a bnode
    private $claim_id   = null;     // the webid for which we have a match
    private $cert_txt   = null;     // textual representation of the certificate
    private $issuer     = null;     // issuer uri
    private $code       = null;     // will hold error codes
    private $verified   = null;     // TLS client private key verification

    const parseError = "Cannot parse WebID";

    const nocert = "No certificates installed in the client's browser";
    
    const certNoOwnership = "No ownership! Could not verify that the client certificate's public key matches their private key";

    const certExpired = "The certificate has expired";
    
    const noVerifiedWebId = "WebId does not match the certificate";
    
    const noURI = "No WebID URIs found in the provided certificate";
    
    const noWebId = "No identity found for existing WebID";
    
    const IdPError = "Other error(s) in the IdP setup. Please warn the IdP administrator";

    /** 
     * Initialize the variables and perfom sanity checks
     *
     * @return boolean
     */
    public function __construct($log)
    {
        // client's browser certificate (in PEM format)
        $this->cert_pem = $_SERVER['SSL_CLIENT_CERT'];

        // if the client certificate's public key matches his private key
        $this->verified = $_SERVER['SSL_CLIENT_VERIFY'];

        // Service Provider (source of request)
        $this->issuer = $_GET['authreqissuer'];

        // set log object
        $this->log = $log;
    
        // set timestamp in XML format
        $this->ts = date("Y-m-dTH:i:sP", time());
    
        // set whether the TLS handshake was successful or not
        $this->verified = $_SERVER['SSL_CLIENT_VERIFY'];

        // check first if we can write in the temp dir
        $tmp = sys_get_temp_dir();
        if ($tmp) {
            // test if we can write to this dir
            $tmpfile = $tmp . "/CRT" . md5(time().rand());
            $handle = fopen($tmpfile, "w") or die("[Runtime Error] Cannot write file to temporary dir (" . $tmpfile . ")!");
      	    fclose($handle);
      	    unlink($tmpfile);
        } else {
            $this->err[] = "[Runtime Error] You have to provide a location to store temporary files!";
        }        
        
        // check if we have openssl installed 
        $command = "openssl version";
        $output = shell_exec($command);
        if (preg_match("/command not found/", $output) == 1) {
            $this->err[] = "[Runtime Error] OpenSSL may not be installed on your host!";
        }
        
        // process certificate contents 
        if ($this->cert_pem) {
            // get the modulus from the browser certificate (ugly hack)
            $tmpCRTname = $tmp . "/CRT" . md5(time().rand());
            // write the certificate into the temporary file
            $handle = fopen($tmpCRTname, "w") or die("[Runtime Error] Cannot open temporary file to store the client's certificate!");
            fwrite($handle, $this->cert_pem);
            fclose($handle);

            // get the hexa representation of the modulus
            // TODO: test values containing leading 0s! (they may get truncated)
          	$command = "openssl x509 -in " . $tmpCRTname . " -modulus -noout";
          	$output = explode('=', shell_exec($command));
            $this->modulus = preg_replace('/\s+/', '', strtolower($output[1]));

            // get the full contents of the certificate
            $command = "openssl x509 -in " . $tmpCRTname . " -noout -text";
            $this->cert_txt = shell_exec($command);
            
            // create a php array with the contents of the certificate
            $this->cert = openssl_x509_parse(openssl_x509_read($this->cert_pem));

            if ( ! $this->cert) {
                $this->err[] = WebIDauth::nocert;
                $this->code = "nocert";
                $this->data = $this->retErr($this->code);
            }
            
            // get subjectAltName from certificate (there might be more stuff in AltName)
            $alt = explode(', ', $this->cert['extensions']['subjectAltName']);
            // find the webid URI
            foreach ($alt as $val) {
                if (strstr($val, 'URI:')) {
                    $webid = explode('URI:', $val);
                    $this->webid[] = $webid[1];
                }
            }
                                
            // delete the temporary certificate file
            unlink($tmpCRTname);
        } else {
            $this->err[] = "[Client Error] You have to provide a certificate!";
        }

        
        // check if everything is good
        if (sizeof($this->err)) {
            $this->getErr();
            exit;
        } else {
            return true;
        }
    }
    
    /**
     * Return the error URL
     * @code = nocert, noVerifiedWebId, noWebId, IdPError
     *
     * @return string
     */
    function retErr($code)
    {
        return $this->issuer . "?error=" . $code;
    }
    
    /**
     * Return the errors
     *
     * @return array
     */
    function getErr()
    {
        $ret = "";
        foreach ($this->err as $error) {
            echo "FATAL: " . $error . "<br/>";
        }
        return $ret;
    }
    
    /**
     * DANGEROUS: returns the object itself.
     * Sould only be used for debugging!
     */
    function dumpVars()
    {
        return $this;
    }

    /**
     * Display an extensive overview of the whole authentication process
     * @return html data
     */
    public function display()
    {
        // display all WebIDs in the certificate
		$ret = "<p>&nbsp;</p>\n";
        $ret .= "Your certificate contains the following WebIDs:<br/>\n";
        $ret .= "<ul>\n";
        if (sizeof($this->webid)) {
            foreach ($this->webid as $webid)
                $ret .= "<li>" . $webid . "</li>\n";
            $ret .= "</ul><br/>\n";
        } else {
            $ret .= "<font color=\"red\">" . WebIDauth::noURI . "!</font><br/></br>\n";
        }

        // display the WebID that got a match
        $ret .= "The WebID URI used to claim your identity is:<br/>\n";
        $ret .= "<ul>\n";
        $ret .= "  <li>" . $this->claim_id . " (your claim was ";
        $ret .= isset($this->claim_id)?'<font color="green">SUCCESSFUL</font>!)':'<font color="red">UNSUCCESSFUL</font>!)';        
        $ret .= "  </li>\n";
        $ret .= "</ul><br/>\n";
        
        // print the url suffix
        $ret .= "The WebID URL suffix (to be signed) for your service provider is:<br/>\n";
        $ret .= "<ul>\n";
        $ret .= "  <li>" . urldecode($this->data) . "</li>\n";
        $ret .= "</ul><br/>\n";

        if (sizeof($this->webid) > 1) {        
            $ret .= "<font color=\"orange\">WARNING:</font> Your modulus has more than one relation to a hexadecimal string. ";
            $ret .= "Unless both of those strings map to the same number, your identification experience will vary across clients.<br/><br/>\n";
        }
        // warn if we have a bnode modulus
        if ($this->is_bnode)
            $ret .= "<font color=\"orange\">WARNING:</font> your modulus is a blank node. The newer specification requires this to be a literal.<br/><br/>\n";
        
        // print errors if any
        if (sizeof($this->err)) {
            $ret .= "Error code:<br/>\n";
            $ret .= "<ul>\n";
            $ret .= "  <li><font color=\"red\">" . $this->code . "</font> " . $this->getErr() . "</li>\n";
            $ret .= "</ul><br/>\n";
        }
        
        // print the certificate in it's raw format
        $ret .= "<p>&nbsp;</p>\n";
        $ret .= "<strong>Certificate in PEM format: </strong><br/>\n";
        $ret .= "<pre>" . $this->cert_pem . "</pre><br/><br/>\n";

        // print the certificate in text format
        $ret .= "<strong>Certificate in text format: </strong><br/>\n";
        $ret .= "<pre>" . $this->cert_txt . "</pre><br/><br/>\n";

        return $ret;
    }
  
    /** 
     * Process the request by comparing the modulus in the public key of the
     * certificate with the modulus in webid profile. If everything is ok, it
     * returns -> $authreqissuer?webid=$webid&ts=$timeStamp, else it returns
     * -> $authreqissuer?error=$errorcode
     *
     * @return boolean 
     */
   
    function processReq($verbose = null, $host = null)
    {
        // get expiration date
        $expire = $this->cert['validTo_time_t'];

        // here we will store verbose messages
        $info = '';
        $info .= "<br/> * Checking ownership of certificate (public key matches private key)...\n";

        // Log steps from now on
        $this->log->LogInfo("[" . $host . "] " . "* Checking ownership of certificate (public key matches private key)...");
        
        // verify client certificate using TLS
        if (($this->verified == 'SUCCESS') || ($this->verified == 'GENEROUS')) {
            $info .= "<font color=\"green\">PASSED</font> <small>(Reason: " . $this->verified . ")</small><br/>\n";
            $this->log->LogInfo("[" . $host . "] " . "  PASSED -> Reason: " . $this->verified . "");
        } else {
            $info .= "<font color=\"red\"></font> <small>(Reason: " . $this->verified . ")</small><br/>\n";
            $this->log->LogInfo("[" . $host . "] " . "  FAILED -> Reason: " . $this->verified . "");
            
            $this->err[] = WebIDauth::certNoOwnership;
            $this->code = "certNoOwnership";
            $this->data = $this->retErr($this->code);
            return false;
        }

        $info .= "<br/> * Checking if certificate contains URIs in the subjectAltName field...\n";
        $this->log->LogInfo("[" . $host . "] " . "* Checking if certificate contains URIs in the subjectAltName field...");
        
        // check if we have URIs
        if (!sizeof($this->webid)) {
            $info .= "<font color=\"red\">FAILED</font><br/>\n";
            $info .= "<font color=\"red\">&nbsp;&nbsp;&nbsp;<small>(Reason: " . WebIDauth::noURI . "!)</small></font><br/>\n";
            $this->log->LogInfo("[" . $host . "] " . "  FAILED -> Reason: " . WebIDauth::noURI . "!)");

            $this->err[] = WebIDauth::noURI;
            $this->code = "noURI";
            $this->data = $this->retErr($this->code);
            return false;
        } else {
            // list total number of webids in the certificate
            $info .= "<font color=\"green\">PASSED</font><br/>\n";
            $info .= "<br/> * Found " . sizeof($this->webid) . " URIs in the certificate (a maximum of 3 will be tested).<br/>\n";
            $this->log->LogInfo("[" . $host . "] " . "  PASSED -> Found " . sizeof($this->webid) . " URIs in the certificate (a maximum of 3 will be tested)");
        }
        
        // default = no match
        $match = false;
        $match_id = array();

        // try to find a match for each webid URI in the certificate
        $i = 0;
        while ($i < sizeof($this->webid)) {
            $webid = $this->webid[$i];

            $curr = $i + 1;
            $info .= "<br/> * Checking URI " . $curr ." <small> (" . $webid . ")</small>...<br/>\n";
            $this->log->LogInfo("[" . $host . "] " . "* Checking URI " . $curr ." (" . $webid . ")...");
            $info .= "&nbsp; - Trying to fetch and process certificate(s) from webid profile...\n";

            // fetch identity for webid profile 
            $graph = new Graphite();
            $graph->load($webid);
            $graph->ns("cert", "http://www.w3.org/ns/auth/cert#");
            $person = $graph->resource($webid);
            $type = $person->type();
            
            $bnode = false;
            $identity = false;

            // check if using the old spec or not
            $old = $graph->allOfType('rsa:RSAPublicKey');
            if (sizeof($old) > 0) {
                $info .= "<br/>&nbsp; - <font color=\"red\">Warning, your WebID contains *at least* a cert representation which uses the old spec...</font>\n";
                $this->log->LogInfo("[" . $host . "] " . "* Warning, your WebID contains *at least* a cert representation which uses the old spec...");
            }

            // parse all certificates contained in the webid document
            foreach ($graph->allOfType('cert:RSAPublicKey') as $certs) {
                $this->log->LogInfo("[" . $host . "] " . "  - Trying to fetch and process certificate(s) from webid profile...PASSED");
                
                $hex = $certs->get('cert:modulus');

                $info .= "<br/>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
                $info .= "Testing if the modulus representation matches the one in the webid ";
                $info .= "(found a modulus value)...<br/>\n";
                $this->log->LogInfo("[" . $host . "] " . "          - Testing if the modulus representation matches the one in the webid -> found a modulus value");
                    
                // clean up string
                $hex = strtolower(preg_replace('/\s+/', '', $hex));
        
                $info .= "<br/>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
                $info .= "Testing modulus...\n";
    
                // check if the two modulus values match
                if ($hex == $this->modulus) {
                    $info .= "<font color=\"green\"> PASSED</font><br/>\n";
                    $info .= "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
                    $info .= "WebID=" . substr($hex, 0, 15) . "......." . substr($hex, strlen($hex) - 15, 15) . "<br/>\n";
                    $info .= "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
                    $info .= "&nbsp;Cert&nbsp; =" . substr($this->modulus, 0, 15) . "......." . substr($this->modulus, strlen($this->modulus) - 15, 15) . "<br/>\n";
                    $this->log->LogInfo("[" . $host . "] " . "              - Testing modulus: ...PASSED");
                    $this->log->LogInfo("[" . $host . "] " . "                  WebID=" . substr($hex, 0, 15) . "......." . substr($hex, strlen($hex) - 15, 15));
                    $this->log->LogInfo("[" . $host . "] " . "                  Cert =" . substr($this->modulus, 0, 15) . "......." . substr($this->modulus, strlen($this->modulus) - 15, 15));

                    $this->data = $this->issuer . (strpos($this->issuer,'?')===false?"?":"&")."webid=" . urlencode($webid) . "&ts=" . urlencode($this->ts);
                    $match = true;
                    $this->claim_id = $webid;
                    $this->is_bnode = $bnode;
                    // we got a match -> exit loop
                    break;
                } else {
                    $info .= "<font color=\"red\">              - FAILED</font><br/>\n";
                    $info .= "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
                    $info .= "WebID=" . substr($hex, 0, 15) . "......." . substr($hex, strlen($hex) - 15, 15) . "<br/>\n";
                    $info .= "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
                    $info .= "&nbsp;Cert&nbsp; =" . substr($this->modulus, 0, 15) . "......." . substr($this->modulus, strlen($this->modulus) - 15, 15) . "<br/>\n";
                    $this->log->LogInfo("[" . $host . "] " . "              - Testing modulus: ...FAILED");
                    $this->log->LogInfo("[" . $host . "] " . "                  WebID=" . substr($hex, 0, 15) . "......." . substr($hex, strlen($hex) - 15, 15));
                    $this->log->LogInfo("[" . $host . "] " . "                  Cert =" . substr($this->modulus, 0, 15) . "......." . substr($this->modulus, strlen($this->modulus) - 15, 15));
                    continue;
                }
                // do not check further identities
                if ($this->claim_id)
                    break;
            } // end foreach($cert)
            
            // exit while loop if we have a match
            if ($match) {
                $info .= "<br/>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<b>Match found, ignoring futher tests!</b><br/>\n";
                $this->log->LogInfo("[" . $host . "] " . "              Match found, ignoring futher tests!");
                break;           
            }
           
            $i++;
        } // end while()

        // we had no match, return false          
        if ( ! $match) {
            $info .= "<br/><br/><font color=\"red\"> * Final conclusion: " . WebIDauth::noVerifiedWebId . "</font><br/>\n";
            $this->log->LogInfo("[" . $host . "] " . "* Final conclusion: " . WebIDauth::noVerifiedWebId);
            
            $this->err[] = WebIDauth::noVerifiedWebId;
            $this->code = "noVerifiedWebId";
            $this->data = $this->retErr($this->code);

            if ($verbose)
                echo $info;

            return false;
        }
        
        // otherwise all is good
        $info .= "<br/><font color=\"green\"> * Authentication successful!</font><br/>\n";
        $this->log->LogInfo("[" . $host . "] " . "* Final conclusion: authentication successful!");
  
        if ($verbose)
            echo $info;
            
        return true;
    } // end function
 
    /** 
     * Redirect user to the Service Provider's page, then exit.
     * The header location is signed with the private key of the IdP 
     */
    public function redirect($key_path)
    {
        // load private key
        if ($key_path) {
            // check if we can open location and then read key
            $fp = fopen($key_path, "r") or die("[Runtime Error] Cannot open private key file!");
            $key = fread($fp, 8192);
            fclose($fp);
        } else {
            exit("[Runtime Error] You have to provide the location of the private key when running in IDP mode!");
        }
		
        // get private key object
        $pkey = openssl_get_privatekey($key);

        // sign data
        openssl_sign($this->data, $signature, $pkey);

        // free the key from memory
        openssl_free_key($pkey);

        // redirect user back to issuer page
        header("Location: " . $this->data . "&sig=" . rtrim(strtr(base64_encode($signature), '+/', '-_'), '=') . "&referer=https://" . $_SERVER["SERVER_NAME"]);
        exit;
    }

} // end class

