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

// client's browser certificate (in PEM format)
$client_cert = $_SERVER['SSL_CLIENT_CERT'];

// Service Provider (source of request)
$issuer = $_GET['authreqissuer'];

// where to store temporary files
// (by default it gets the tmp directory)
$tmpDir = sys_get_temp_dir();

// private key belonging to server's SSL certificate
$server_key = "/etc/ssl/private/server.key";


/* ------ DO NOT MODIFY BELOW THIS LINE ------   */

// display certificate contents if told to
if ($_GET['display']) {
    // test if we can write to the tmp dir
    $tmpfile = $tmpDir . "/INFO" . md5(time().rand());
    $handle = fopen($tmpfile, "w") or die("Cannot write file to temporary dir (" . $tmpfile . ")!");
    fclose($handle);
    unlink($tmpfile);

    // print the certificate in it's raw format
    echo "<pre>" . $client_cert . "</pre><br/><br/>\n";

    // get the modulus from the browser certificate (ugly hack)
    $tmpCRTname = $tmpDir . "/INFO" . md5(time().rand());
    // write the certificate into the temporary file
    $handle = fopen($tmpCRTname, "w");
    fwrite($handle, $client_cert);
    fclose($handle);

    $command = "openssl x509 -in $tmpCRTname -text -noout";
    $output = shell_exec($command);
    // delete the temporary CRT file
    unlink($tmpCRTname);
    
    // print output
    echo "<pre>" . $output . "</pre>\n";

} else if (strlen($issuer) > 0) {
	// process the request if we have an issuer
	$auth = new WebIDauth($client_cert, $issuer, $tmpDir);

    if ($auth) {
       	$auth->processReq();
   	    $auth->redirect();
	}
} else {
	// display how to proceed 
	echo "<font color=\"red\">You have not provided the Service Provider's URI!</font><br/>\n";
	echo "Either go to <a href=\"https://auth.fcns.eu/\">https://auth.fcns.eu/</a> and use the form at the top of the page, or append <b>?authreqissuer=http://YourServerURI</b> after the browser's URL.\n";
}

?>
