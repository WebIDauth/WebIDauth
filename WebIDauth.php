<?
//-----------------------------------------------------------------------------------------------------------------------------------
//
// Filename   : WebIDauth.php
// Date       : 5th Apr 2011
//
// Version 0.2
// 
// Copyright 2011 fcns.eu
// Author: Andrei Sambra - andrei@fcns.eu
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

require_once('graphite.php');
require_once('arc/ARC2.php');

/**
 * Implements WebID Authentication
 * seeAlso https://foafssl.org/srv/idp
 *
 * If successfull, it redirects the user to the Service Provider's URI
 * adding information like webid, timestamp (signing them with the IdP's
 * private key). 
 * Ex. for Service Provider http://webid.fcns.eu it will return:
 * http://webid.fcns.eu/index.php?webid=$webid&ts=$timeStamp&sig=$URLSignature
 */
class WebIDauth {
    public  $err        = array(); // will hold our errors for diagnostics
    private $webid      = array(); // webid URIs
    private $ts         = null; // timestamp in W3C XML format
    private $cert       = null; // php array with the contents of the certificate
    private $cert_pem   = null; // certificate in pem format
    private $modulus    = null; // modulus component of the public key
    private $exponent   = null; // exponent component of the public key
    private $is_bnode   = false; // if the modulus is expressed as a bnode
    private $claim_id   = null; // the webid for which we have a match
    private $cert_txt   = null; // textual representation of the certificate
    private $issuer     = null; // issuer uri
    private $tmp        = null; // location to store temporary files needed by openssl 
    private $code       = null; // will hold error codes
    private $verified   = null; // TLS client private key verification

    private $privKey = null; // private key of the IdP's SSL certificate (this server)

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
    public function __construct($log,
                                $certificate = null,
                                $issuer = null,
                                $tmp = null,
                                $verified = null,
                                $privKey = null,
                                $protocol = null
                                )
    {
        // set log object
        $this->log = $log;
    
        // check for desired protocol (TLSv1 at least)
        if ($protocol != 'TLSv1') {
            $this->err[] = "[SSL Error] TLSv1 required. (found ". $protocol . ")";
            $this->log->LogInfo("[" . $host . "] " . "* TLSv1 required - found ". $protocol . "..."); 
        }

        // set timestamp in XML format
        $this->ts = date("Y-m-dTH:i:sP", time());
    
        // set whether the TLS handshake was successful or not
        $this->verified = $verified;

        // check first if we can write in the temp dir
        if ($tmp) {
            $this->tmp = $tmp;
            // test if we can write to this dir
            $tmpfile = $this->tmp . "/CRT" . md5(time().rand());
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
        if ($certificate) {
            // set the certificate in pem format
            $this->cert_pem = $certificate;

            // get the modulus from the browser certificate (ugly hack)
            $tmpCRTname = $this->tmp . "/CRT" . md5(time().rand());
            // write the certificate into the temporary file
            $handle = fopen($tmpCRTname, "w") or die("[Runtime Error] Cannot open temporary file to store the client's certificate!");
            fwrite($handle, $this->cert_pem);
            fclose($handle);

            // get the hexa representation of the modulus
          	$command = "openssl x509 -in " . $tmpCRTname . " -modulus -noout";
          	$output = explode('=', shell_exec($command));
            $this->modulus = preg_replace('/\s+/', '', strtolower($output[1]));

            // get the full contents of the certificate
            $command = "openssl x509 -in " . $tmpCRTname . " -noout -text";
            $this->cert_txt = shell_exec($command);
            
            // create a php array with the contents of the certificate
            $this->cert = openssl_x509_parse(openssl_x509_read($this->cert_pem));

            if (!$this->cert) {
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

        // process issuer
        if ($issuer)
            $this->issuer = $issuer;
             
        // load private key
        if ($privKey) {
            // check if we can open location and then read key
            $fp = fopen($privKey, "r") or die("[Runtime Error] Cannot open privte key file for the server's SSL certificate!");
            $this->privKey = fread($fp, 8192);
            fclose($fp);
        } else {
            $this->err[] = "[Runtime Error] You have to provide the location of the server SSL certificate's private key!";
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
     * DANGEROUS:returns the object itself.
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

        if (sizeof($this->webid) > 1)         
            $ret .= "<font color=\"orange\">WARNING:</font> Your modulus has more than one relation to a hexadecimal string. ";
            $ret .= "Unless both of those strings map to the same number, your identification experience will vary across clients.<br/><br/>\n";
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
        // maximum of 3 URIs per certificate - to prevent DoS
        $i = 0;
		if (sizeof($this->webid) >= 3)
			$max = 3;
		else
			$max = sizeof($this->webid);
        while ($i < $max) {
            $webid = $this->webid[$i];

    		$curr = $i + 1;
            $info .= "<br/> * Checking URI " . $curr ." <small> (" . $webid . ")</small>...<br/>\n";
            $this->log->LogInfo("[" . $host . "] " . "* Checking URI " . $curr ." (" . $webid . ")...");

            // fetch identity for webid profile 
            $graph = new Graphite();
            $graph->load($webid);
            $person = $graph->resource($webid);

            $info .= "&nbsp; - Trying to fetch and process certificate(s) from webid profile...\n";

            $bnode = false;
			$identity = false;
            // parse all certificates contained in the webid document
            foreach ($graph->allOfType('http://www.w3.org/ns/auth/rsa#RSAPublicKey') as $certs) {
                $identity = $certs->get('http://www.w3.org/ns/auth/cert#identity');
 
				$info .= "<font color=\"green\">PASSED</font><br/>\n";
                $info .= "&nbsp;&nbsp;&nbsp; - Testing if the client's identity matches the one in the webid...\n";
                $this->log->LogInfo("[" . $host . "] " . "  - Trying to fetch and process certificate(s) from webid profile...PASSED");

				
                // proceed if the identity of subjectAltName matches one identity in the webid 
                if ($identity == $webid) {
                    $info .= "<font color=\"green\">PASSED</font><br/>\n";
                    $this->log->LogInfo("[" . $host . "] " . "      - Testing if the client's identity matches the one in the webid...PASSED");
                    // save the URI if it matches an identity
                    $match_id[] = $webid;
                    
                    // get corresponding resources for modulus and exponent
                    if (substr($certs->get('http://www.w3.org/ns/auth/rsa#modulus'), 0, 2) == '_:') {
                        $mod = $graph->resource($certs->get('http://www.w3.org/ns/auth/rsa#modulus'));
                        $hex = $mod->all('http://www.w3.org/ns/auth/cert#hex')->join(',');
                        $bnode = true;
                    } else {
                        $hex = $certs->get('http://www.w3.org/ns/auth/rsa#modulus');
                    }

                    // uglier but easier to process
                    $hex_vals = explode(',', $hex);

                    $info .= "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
                    $info .= "Testing if the modulus representation matches the one in the webid ";
                    $info .= "(found <font color=\"red\">" . sizeof($hex_vals) . "</font> modulus values)...<br/>\n";
                    $this->log->LogInfo("[" . $host . "] " . "          - Testing if the modulus representation matches the one in the webid -> found " . sizeof($hex_vals) . " modulus values");
                    
                    
                    // go through each key and check if it matches
                    foreach ($hex_vals as $key => $hex) {
                        // clean up strings
                		$hex = strtolower(preg_replace('/\s+/', '', $hex));
		
                        $info .= "<br/>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
                        $info .= "Testing modulus: " . ($key + 1) . "/" . sizeof($hex_vals) . "...\n";
	
	        	        // check if the two modulus values match
                        if ($hex == $this->modulus) {
                            $info .= "<font color=\"green\">              * Testing modulus: " . ($key + 1) . "/" . sizeof($hex_vals) . "...PASSED</font><br/>\n";
                            $info .= "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
            				$info .= "WebID=" . substr($hex, 0, 15) . "......." . substr($hex, strlen($hex) - 15, 15) . "<br/>\n";
        					$info .= "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
        	                $info .= "&nbsp;Cert&nbsp; =" . substr($this->modulus, 0, 15) . "......." . substr($this->modulus, strlen($this->modulus) - 15, 15) . "<br/>\n";
        	                $this->log->LogInfo("[" . $host . "] " . "              - Testing modulus: " . ($key + 1) . "/" . sizeof($hex_vals) . "...PASSED");
        	                $this->log->LogInfo("[" . $host . "] " . "                  WebID=" . substr($hex, 0, 15) . "......." . substr($hex, strlen($hex) - 15, 15));
        	                $this->log->LogInfo("[" . $host . "] " . "                  Cert =" . substr($this->modulus, 0, 15) . "......." . substr($this->modulus, strlen($this->modulus) - 15, 15));

                            $this->data = $this->issuer . "?webid=" . urlencode($webid) . "&ts=" . urlencode($this->ts);
                            $match = true;
                            $this->claim_id = $webid;
                            $this->is_bnode = $bnode;
                            // we got a match -> exit loop
                            break;
                        } else {
                            $info .= "<font color=\"red\">              * Testing modulus: " . ($key + 1) . "/" . sizeof($hex_vals) . "...FAILED</font><br/>\n";
                            $info .= "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
           					$info .= "WebID=" . substr($hex, 0, 15) . "......." . substr($hex, strlen($hex) - 15, 15) . "<br/>\n";
       						$info .= "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
      						$info .= "&nbsp;Cert&nbsp; =" . substr($this->modulus, 0, 15) . "......." . substr($this->modulus, strlen($this->modulus) - 15, 15) . "<br/>\n";
      						$this->log->LogInfo("[" . $host . "] " . "              - Testing modulus: " . ($key + 1) . "/" . sizeof($hex_vals) . "...FAILED");
        	                $this->log->LogInfo("[" . $host . "] " . "                  WebID=" . substr($hex, 0, 15) . "......." . substr($hex, strlen($hex) - 15, 15));
        	                $this->log->LogInfo("[" . $host . "] " . "                  Cert =" . substr($this->modulus, 0, 15) . "......." . substr($this->modulus, strlen($this->modulus) - 15, 15));
                            continue;
                        }
                    }
                } else {
                    $info .= "<font color=\"red\">FAILED</font><br/>\n";
                    $this->log->LogInfo("[" . $host . "] " . "      - Testing if the client's identity matches the one in the webid...FAILED");
                }
                // do not check further identities
                if ($this->claim_id)
                    break;
            } // end foreach($cert)

            // failed to find an identity at the specified WebID URI 
			if (!$identity) {
                $info .= "<font color=\"red\">FAILED</font><br/>\n";
                $this->log->LogInfo("[" . $host . "] " . "  - Trying to fetch and process certificate(s) from webid profile...FAILED");
			}
			// exit while loop if we have a match
			if ($match) {
                $info .= "<br/>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<b>Match found, ignoring futher tests!</b><br/>\n";
                $this->log->LogInfo("[" . $host . "] " . "              Match found, ignoring futher tests!");
				break;           
            }
            
            $i++;
        } // end while()

        // we had no match, return false          
        if (!$match) {
            $info .= "<br/><font color=\"red\"> * Final conclusion: " . WebIDauth::noVerifiedWebId . "</font><br/>\n";
            $this->log->LogInfo("[" . $host . "] " . "* Final conclusion: " . WebIDauth::noVerifiedWebId);
            
            $this->err[] = WebIDauth::noVerifiedWebId;
            $this->code = "noVerifiedWebId";
            $this->data = $this->retErr($this->code);
            return false;
        }
        // if no identity is found, return false
        if (!sizeof($match_id)) {
            $info .= "<br/><font color=\"red\"> * " . WebIDauth::noWebId . "</font><br/>\n";
            $this->log->LogInfo("[" . $host . "] " . "* Final conclusion: " . WebIDauth::noWebId);
            
            $this->err[] = WebIDauth::noWebId;
            $this->code = "noWebId";
            $this->data = $this->retErr($this->code);
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
    public function redirect()
    {
        // get private key object
        $pkey = openssl_get_privatekey($this->privKey);

        // sign data
        openssl_sign($this->data, $signature, $pkey);

        // free the key from memory
        openssl_free_key($pkey);

        // redirect user back to issuer page
        header("Location: " . $this->data . "&sig=" . urlencode(base64_encode($signature)) . "&referer=https://" . $_SERVER["SERVER_NAME"]);
        exit;
    }

} // end class

?>
