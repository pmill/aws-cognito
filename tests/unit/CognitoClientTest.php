<?php
namespace pmill\AwsCognito\Tests\Unit;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\ResultInterface;
use Faker\Factory;
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

    private $faker;

    /** @var CognitoIdentityProviderClient */
    private $cognitoIdentityProviderClientMock;
    private $cognitoClient;

    public function setUp(): void
    {
        $this->faker = Factory::create();

        $this->cognitoIdentityProviderClientMock = $this
            ->getMockBuilder(CognitoIdentityProviderClient::class)
            ->addMethods(['adminInitiateAuth'])
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

        $rawResponseArray = ['AuthenticationResult' => true];
        $response = $this->createMock(ResultInterface::class);
        $response->expects(static::once())
            ->method('toArray')
            ->willReturn($rawResponseArray);

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
            ->willReturn($response);

        $result = $this->cognitoClient->authenticate($username, $password);

        $this->assertSame($rawResponseArray['AuthenticationResult'], $result);
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
