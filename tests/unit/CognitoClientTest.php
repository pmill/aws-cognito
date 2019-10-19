<?php
namespace pmill\AwsCognito\Tests\Unit;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\ResultInterface;
use Faker\Factory;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use pmill\AwsCognito\CognitoClient;

class CognitoClientTest extends TestCase
{
    private const CONFIG = [
        'credentials' => [
            'key' => 'key_test',
            'secret' => 'secret_test',
        ],
        'region' => 'eu-west-1',
        'version' => 'latest',
        'app_client_id' => 'app_client_id_test',
        'app_client_secret' => 'app_client_secret_test',
        'user_pool_id' => 'user_pool_id_test',
    ];

    private const RAW_RESPONSE_ARRAY = ['AuthenticationResult' => true];

    private $faker;

    /** @var CognitoIdentityProviderClient */
    private $cognitoIdentityProviderClientMock;
    private $cognitoClient;

    public function setUp(): void
    {
        $this->faker = Factory::create();

        $this->cognitoIdentityProviderClientMock = $this
            ->getMockBuilder(CognitoIdentityProviderClient::class)
            ->addMethods([
                'adminInitiateAuth',
                'respondToAuthChallenge',
            ])
            ->disableOriginalConstructor()
            ->getMockForAbstractClass()
        ;

        $this->cognitoClient = new CognitoClient($this->cognitoIdentityProviderClientMock);
        $this->cognitoClient->setAppClientId(self::CONFIG['app_client_id']);
        $this->cognitoClient->setAppClientSecret(self::CONFIG['app_client_secret']);
        $this->cognitoClient->setRegion(self::CONFIG['region']);
        $this->cognitoClient->setUserPoolId(self::CONFIG['user_pool_id']);
    }

    public function testAuthenticate(): void
    {
        $username = $this->faker->userName;
        $password = $this->faker->password;

        $this->cognitoIdentityProviderClientMock->expects(static::once())
            ->method('adminInitiateAuth')
            ->with([
                'AuthFlow' => 'ADMIN_NO_SRP_AUTH',
                'AuthParameters' => [
                    'USERNAME' => $username,
                    'PASSWORD' => $password,
                    'SECRET_HASH' => $this->cognitoSecretHash($username),
                ],
                'ClientId' => self::CONFIG['app_client_id'],
                'UserPoolId' => self::CONFIG['user_pool_id'],
            ])
            ->willReturn($this->getBasicResponse());

        $result = $this->cognitoClient->authenticate($username, $password);

        $this->assertSame(self::RAW_RESPONSE_ARRAY['AuthenticationResult'], $result);
    }

    public function testRespondToAuthChallenge(): void
    {
        $availableChallengeNames = [
            'SMS_MFA',
            'SOFTWARE_TOKEN_MFA',
            'SELECT_MFA_TYPE',
            'MFA_SETUP',
            'PASSWORD_VERIFIER',
            'CUSTOM_CHALLENGE',
            'DEVICE_SRP_AUTH',
            'DEVICE_PASSWORD_VERIFIER',
            'ADMIN_NO_SRP_AUTH',
            'NEW_PASSWORD_REQUIRED',
        ];
        $challengeName = $this->faker->randomElement($availableChallengeNames);
        $challengeResponses =$this->faker->randomElements($availableChallengeNames, 2);
        $session = $this->faker->uuid;

        $this->cognitoIdentityProviderClientMock->expects(static::once())
            ->method('respondToAuthChallenge')
            ->with([
                'ChallengeName' => $challengeName,
                'ChallengeResponses' => $challengeResponses,
                'ClientId' => self::CONFIG['app_client_id'],
                'Session' => $session,
            ])
            ->willReturn($this->getBasicResponse());

        $result = $this->cognitoClient->respondToAuthChallenge($challengeName, $challengeResponses, $session);

        $this->assertSame(self::RAW_RESPONSE_ARRAY['AuthenticationResult'], $result);
    }

    public function testRespondToNewPasswordRequiredChallenge(): void
    {
        $username = $this->faker->userName;
        $newPassword = $this->faker->password;
        $session = $this->faker->uuid;

        $this->cognitoIdentityProviderClientMock->expects(static::once())
            ->method('respondToAuthChallenge')
            ->with([
                'ChallengeName' => 'NEW_PASSWORD_REQUIRED',
                'ChallengeResponses' => [
                    'NEW_PASSWORD' => $newPassword,
                    'USERNAME' => $username,
                    'SECRET_HASH' => $this->cognitoSecretHash($username),
                ],
                'ClientId' => self::CONFIG['app_client_id'],
                'Session' => $session,
            ])
            ->willReturn($this->getBasicResponse());

        $result = $this->cognitoClient->respondToNewPasswordRequiredChallenge($username, $newPassword, $session);

        $this->assertSame(self::RAW_RESPONSE_ARRAY['AuthenticationResult'], $result);
    }

    public function testRefreshAuthentication(): void
    {
        $username = $this->faker->userName;
        $refreshToken = $this->faker->word;

        $this->cognitoIdentityProviderClientMock->expects(static::once())
            ->method('adminInitiateAuth')
            ->with([
                'AuthFlow' => 'REFRESH_TOKEN_AUTH',
                'AuthParameters' => [
                    'USERNAME' => $username,
                    'REFRESH_TOKEN' => $refreshToken,
                    'SECRET_HASH' => $this->cognitoSecretHash($username),
                ],
                'ClientId' => self::CONFIG['app_client_id'],
                'UserPoolId' => self::CONFIG['user_pool_id'],
            ])
            ->willReturn($this->getBasicResponse());

        $result = $this->cognitoClient->refreshAuthentication($username, $refreshToken);

        $this->assertSame(self::RAW_RESPONSE_ARRAY['AuthenticationResult'], $result);
    }

    private function getBasicResponse(): MockObject
    {
        $response = $this->createMock(ResultInterface::class);
        $response->expects(static::once())
            ->method('toArray')
            ->willReturn(self::RAW_RESPONSE_ARRAY);

        return $response;
    }

    private function cognitoSecretHash($username)
    {
        $hash = hash_hmac(
            'sha256',
            $username . self::CONFIG['app_client_id'],
            self::CONFIG['app_client_secret'],
            true
        );

        return base64_encode($hash);
    }
}
