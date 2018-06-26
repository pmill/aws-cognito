<?php
/** @var \pmill\AwsCognito\CognitoClient $client */
$client = require(__DIR__ . '/bootstrap.php');


$username = 'test@example.com';
$groupName = 'initial_aws_user_group';

$client->addUserToGroup($username, $groupName);

