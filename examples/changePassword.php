<?php
/** @var \pmill\AwsCognito\CognitoClient $client */
$client = require(__DIR__ . '/bootstrap.php');

$username = 'test@example.com';
$password = 'Pass1worD';
$newPassword = 'Pass2worD';

$authenticationResponse = $client->authenticate($username, $password);
$accessToken = $authenticationResponse['AccessToken'];

$client->changePassword($accessToken, $password, $newPassword);
