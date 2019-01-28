<?php
/** @var \pmill\AwsCognito\CognitoClient $client */
$client = require(__DIR__ . '/bootstrap.php');

$username = 'test@example.com';

try {
    $groups = $client->getGroupsForUsername($username);
    echo $groups['Groups'].PHP_EOL;
} catch (Exception $e) {
    echo "An error occurred: ".$e->getMessage();
}
