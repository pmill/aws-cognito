<?php

/** @var \pmill\AwsCognito\CognitoClient $client */
$client = require(__DIR__ . '/bootstrap.php');

$username = 'test@example.com';
$password = 'S3cr3T';

$authenticationResponse = $client->authenticate($username, $password);
$accessToken = $authenticationResponse['AccessToken'];

try {
    $user = $client->getUserByToken($accessToken);
    echo $user['Username'].PHP_EOL;
    var_dump($user['UserAttributes']);
} catch (Exception $e) {
    echo "An error occurred: ".$e->getMessage();
}
