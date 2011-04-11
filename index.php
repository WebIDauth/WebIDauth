<?
//-----------------------------------------------------------------------------------------------------------------------------------
//
// Filename   : index.php
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

require_once('WebIDauth.php');

/* Configuration variables (you can modify these) */

// where to store temporary files
// (by default it gets the tmp directory)
$tmpDir = sys_get_temp_dir();

// private key belonging to server's SSL certificate
$server_key = "/var/ssl/server.key";


/* ------ DO NOT MODIFY BELOW THIS LINE ------   */

// client's browser certificate (in PEM format)
$client_cert = $_SERVER['SSL_CLIENT_CERT'];

// Service Provider (source of request)
$issuer = $_GET['authreqissuer'];

// instantiate the WebIDauth class
$auth = new WebIDauth($client_cert, $issuer, $tmpDir, $server_key);
$success = $auth->processReq();


// 
if ($auth) {
    // display certificate contents if told to
    if ($_GET['display']) {
        $auth->display();

    } else {
        if (strlen($issuer) > 0) {
      	    $auth->redirect();
    	} else {
            // display how to proceed 
    	    echo "<font color=\"red\">You have not provided the Service Provider's URI!</font><br/>\n";
	        echo "Either go to <a href=\"https://auth.fcns.eu/\">https://auth.fcns.eu/</a> and use the form at the top of the page, or append <b>?authreqissuer=http://YourServerURI/</b> after the browser's URL.\n";
        }
    }
}
?>
