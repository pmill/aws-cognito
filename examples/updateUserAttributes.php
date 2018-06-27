<?php
/** @var \pmill\AwsCognito\CognitoClient $client */
$client = require(__DIR__ . '/bootstrap.php');


$username = 'test@example.com';
$email = 'newmail@examlpe.com';

$client->updateUserAttributes($username, [
    "email" => $email,
    "custom:myvar" => "Foo42"
    ]);

