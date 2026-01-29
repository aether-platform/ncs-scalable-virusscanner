<?php

require_once 'vendor/autoload.php';

use Appwrite\ClamAV\Network;

if ( isset( $argv[1] )) {
  $ip = gethostbyname($argv[1]); 
} else {
  $ip = '127.0.0.1';
}

$clam = new Network( $ip, 3310); // Or use new Pipe() for unix socket

$clam->ping(); // Check ClamAV is up and running

echo "Version: " . $clam->version(). "\n"; // Check ClamAV version
if ($clam->fileScanInStream(__FILE__) === false ) {
    echo "Test 1 failed\n";
    exit(1);
}

$virus="GIF89a\n<?php\n echo\n 'hacked'\n;\n ?>";
file_put_contents('virus-test-signature-1.virus', $virus );
if ($clam->fileScanInStream('virus-test-signature-1.virus') === true ) {
    echo "Test 2 failed\n";
    exit(1);
}

$virus1 ='X5O!P%@AP[4\PZX54(P^)7CC)7}';
$virus2 ='$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
file_put_contents('virus-test-signature-2.virus', $virus1 . $virus2);
if ($clam->fileScanInStream('virus-test-signature-2.virus') === true ) {
    echo "Test 3 failed\n";
    exit(1);
}
echo "Tests successfull\n";