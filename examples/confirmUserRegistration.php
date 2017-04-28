<?php
/** @var \pmill\AwsCognito\CognitoClient $client */
$client = require(__DIR__ . '/bootstrap.php');

$confirmationCode = '860623';
$username = 'test@example.com';

$client->confirmUserRegistration($confirmationCode, $username);

//You can now login, run login.php test now with your username/password

