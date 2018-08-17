<?php
/** @var \pmill\AwsCognito\CognitoClient $client */
$client = require(__DIR__ . '/bootstrap.php');

$username = 'test@example.com';

try {
    $user = $client->getUser($username);
    echo $user['Username'].PHP_EOL;
    var_dump($user['UserAttributes']);
} catch (pmill\AwsCognito\Exception\UserNotFoundException $e) {
    echo "User not found: $username";
} catch (Exception $e) {
    echo "An error occurred: ".$e->getMessage();
}
