<?php

namespace Sbominator\Scaninator;

require 'vendor/autoload.php';

if ('cli' !== php_sapi_name()) {
    throw new \Exception('This script must be run from the command line.');
}

if (! isset($argv[1])) {
    echo 'Usage: php sca.php <filename or GitHub URL>' . PHP_EOL;
    echo 'Example local file: php sca.php path/to/file.php' . PHP_EOL;
    echo 'Example GitHub URL: https://github.com/owner/repo/blob/main/path/to/file.php' . PHP_EOL;
    exit(1);
}

$scanner      = new Scaninator($argv[1]);
$dependencies = $scanner->getDependecies();

if (empty($dependencies)) {
    echo 'No dependencies found.' . PHP_EOL;
} else {
    echo 'Dependencies found:' . PHP_EOL;
    echo json_encode($dependencies, JSON_PRETTY_PRINT) . PHP_EOL;
}
