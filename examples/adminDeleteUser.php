<?php
/** @var \pmill\AwsCognito\CognitoClient $client */
$client = require(__DIR__ . '/bootstrap.php');


$username = 'test@example.com';

$client->adminDeleteUser($username);