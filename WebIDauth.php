<?
//-----------------------------------------------------------------------------------------------------------------------------------
//
// Filename   : WebIDauth.php
// Date       : 5th Apr 2011
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
    public $err     = array(); // will hold our errors for diagnostics
    private $ts     = NULL; // timestamp in W3C XML format
    private $cert    = NULL; // certificate in pem format
    private $issuer  = NULL; // issuer uri
    private $privKey = NULL; // private key of the IdP's SSL certificate (this server)
    private $tmp    = NULL; // location to store temporary files needed by openssl 
    private $code    = NULL; // will hold error codes

    const nocert = "No certificates installed in the client's browser.";
    
    const certExpired = "The certificate has expired";
    
    const noVerifiedWebId = "WebId does not match the certificate.";
    
    const noWebId = "No identity found for existing WebID.";
    
    const IdPError = "Other error(s) in the IdP setup. Please warn the IdP administrator.";

    /** 
     * Initialize the variables and perfom sanity checks
     * "/etc/apache2/keys/ssl-cert-rena.key"
     * @return boolean
     */
    public function __construct($certificate = NULL,
                                $issuer = NULL,
                                $tmp = NULL,
                                $privKey = NULL)
    {
        $this->ts = date("Y-m-dTH:i:sP", time());
    
        if ($certificate) {
            $this->cert = $certificate;
        } else {
            $this->err[] = "You have to provide a certificate!";
        }

        if ($issuer) {
            $this->issuer = $issuer;
        } else {
            $this->err[] = "You have to provide an URI for the issuer!";
        }
        
        if ($tmp) {
            $this->tmp = $tmp;
            // test if we can write to this dir
            $tmpfile = $this->tmp . "/CRT" . md5(time().rand());
            $handle = fopen($tmpfile, "w") or die("Cannot write file to temporary dir (" . $tmpfile . ")!");
      	    fclose($handle);
      	    unlink($tmpfile);
        } else {
            $this->err[] = "You have to provide a location to store temporary files!";
        }
        
        if ($privKey) {
            // check if we can open location and then read key
            $fp = fopen($privKey, "r") or die("Cannot open privte key file for the server's SSL certificate!");
            $this->privKey = fread($fp, 8192);
            fclose($fp);
        } else {
            $this->err[] = "You have to provide the location of the server SSL certificate's private key!";
        }

        // check if we have openssl installed 
        $command = "openssl version";
        $output = shell_exec($command);
        if (preg_match("/command not found/", $output) == 1) {
            $this->err[] = "OpenSSL may not be installed on your host!";
        }

        // check if everything is good
        if (sizeof($this->err)) {
            $this->getErr();
            return false;
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
            echo "Error: " . $error . "<br/>";
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
     * Process the request by comparing the modulus in the public key of the
     * certificate with the modulus in webid profile. If everything is ok, it
     * returns -> $authreqissuer?webid=$webid&ts=$timeStamp, else it returns
     * -> $authreqissuer?error=$errorcode
     *
     * @return boolean 
     */
    function processReq()
    {
        $crt = openssl_x509_parse($this->cert);

        if (!$crt) {
            $this->err = $this->nocert;
            $this->code = "nocert";
            $this->data = $this->retErr($this->code);
        }

        // get expiration date
        $expire = $crt['validTo_time_t'];
    
        // do not proceed if certificate has expired
        if (time() > $expire) {
            $this->err = $this->certExpired;
            $this->code = "certExpired";
            $this->data = $this->retErr($this->code);
        }
        
        // get subjectAltName from certificate (there might be more stuff in AltName)
        $alt = explode(', ', $crt['extensions']['subjectAltName']);
        echo "<pre>" . print_r($alt, true) . "</pre>";

        // find the webid URI
        foreach ($alt as $val) {
            if (strstr($val, 'URI:')) {
                $webid = explode('URI:', $val);
                $webid = $webid[1];
                break;
            }
        }

        // get identity for webid profile 
        $graph = new Graphite();
        $graph->load($webid);
        $person = $graph->resource($webid);

        // check if we have a valid resource structure
        if (!$person) {
            $this->err = "[CRITICAL] Cannot build resource graph for WebID: " . $webid;
            $this->code = "IdPError";
            $this->data = $this->retErr($this->code);
        }

        // parse all certificates contained in the webid document
        foreach ($graph->allOfType('http://www.w3.org/ns/auth/rsa#RSAPublicKey') as $certs) {
            $identity = $certs->get('http://www.w3.org/ns/auth/cert#identity');
    
            // proceed if the identity of subjectAltName matches one identity in the webid 
            if ($identity == $webid) {
                // get corresponding resources for modulus and exponent
                if (substr($certs->get('http://www.w3.org/ns/auth/rsa#modulus'), 0, 2) == '_:') {
                    $mod = $graph->resource($certs->get('http://www.w3.org/ns/auth/rsa#modulus'));
                    $hex = $mod->all('http://www.w3.org/ns/auth/cert#hex')->join(',');
                } else {
                    $hex = $certs->get('http://www.w3.org/ns/auth/rsa#modulus');
                }
                           
                // get the modulus from the browser certificate (ugly hack)
                $tmpCRTname = $this->tmp . "/CRT" . md5(time().rand());
                // write the certificate into the temporary file
        	    $handle = fopen($tmpCRTname, "w");
        	    fwrite($handle, $this->cert);
                fclose($handle);

                // get the hexa representation of the modulus
            	$command = "openssl x509 -in $tmpCRTname -modulus -noout";
            	$output = explode('=', shell_exec($command));
            	$output = $output[1];
                $modulus = preg_replace('/\s+/', '', strtolower($output));
            	// delete the temporary CRT file
            	unlink($tmpCRTname);

                // uglier but easier to process
                $hex_vals = explode(',', $hex);
                
                $ok = 0;
                // go through each key and check if it matches
                foreach ($hex_vals as $hex) {
                    // clean up strings
            		$hex = preg_replace('/\s+/', '', $hex);
		
	    	        // check if the two modulus values match
                    if ($hex == $modulus) {
                        $this->data = $this->issuer . "?webid=" . urlencode($webid) . "&ts=" . urlencode($this->ts);
                        $ok = 1;

                        break;
                    } else {
                        continue;
                    }
                }
                // we had no match            
                if ($ok == 0) {
                    $this->err = $this->noVerifiedWebId;
                    $this->code = "noVerifiedWebId";
                    $this->data = $this->retErr($this->code);
                }
            } // we have no matching identity in the webid profile
            else {
                $this->err = $this->noWebId;
                $this->code = "noWebId";
                $this->data = $this->retErr($this->code);
            }
        } // end foreach
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
