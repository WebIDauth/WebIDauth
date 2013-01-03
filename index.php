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

require_once('WebIDauth.php');
require_once('logger.php');

/* Configuration variables (you can modify these) */

// log requests (for debugging purposes)
$log = new KLogger( "logfile.log" , KLogger::DEBUG );

// private key required if we act as IDP (sign redirected request)
$key_path = "/var/ssl/server.key";

/* ------ DO NOT MODIFY BELOW THIS LINE ------   */

// instantiate the WebIDauth class
$auth = new WebIDauth($log);


// do the magic stuff :-)
if ($auth) {
    // display certificate contents if told to
    if ($_GET['verbose']) {
        // log who is accessing the service (might be needed later for debugging)
        $log->LogInfo("[VERBOSE] From: " . $_SERVER["HTTP_HOST"]);
		// true - means to enable verbose authentication
        echo "<table style=\"margin: 0.5em; padding:0.5em; background-color:#fff; border:dashed 1px grey;\"><tr><td>\n";
        $success = $auth->processReq($_GET['verbose'], $_SERVER["HTTP_HOST"]);
        echo "</td></tr></table>\n";
		echo $auth->display();	
    } else {
        // log who is accessing the service (might be needed later for debugging)
        $log->LogInfo("[AUTHENTICATING] From: " . $_SERVER["HTTP_HOST"] . " => " . $issuer);
        if (strlen($issuer) > 0) {
			$auth->processReq(false, $_SERVER["HTTP_HOST"]);
      	    $auth->redirect($key_path);
    	} else {
            // display how to proceed 
    	    echo "<font color=\"red\">You have not provided the Service Provider's URI!</font><br/>\n";
	        echo "Either go to <a href=\"https://auth.fcns.eu/\">https://auth.fcns.eu/</a> and use the form at the top of the page, or append <b>?authreqissuer=http://YourServerURI/</b> after the browser's URL.\n";
        }
    }
}
?>
