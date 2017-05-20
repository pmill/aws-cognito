<?php
/** @var \pmill\AwsCognito\CognitoClient $client */
$client = require(__DIR__ . '/bootstrap.php');

$username = 'test@example.com';
$refreshToken = 'refresh-token';

$refreshResponse = $client->refreshAuthentication($username, $refreshToken);
var_dump($refreshResponse);
