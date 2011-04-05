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
$issuer = $_REQUEST['authreqissuer'];

// where to store temporary files
// (by default it gets the tmp directory)
$tmpDir = sys_get_temp_dir();

// private key belonging to server's SSL certificate
$server_key = "/etc/apache2/keys/ssl-cert-rena.key"; 


/* ------ DO NOT MODIFY BELOW THIS LINE ------   */

// initialize authention
$auth = new WebIDauth($client_cert, $issuer, $tmpDir, $server_key);

if ($auth) {
    $auth->processReq();
    $auth->redirect();
}
?>
