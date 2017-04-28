<?php
namespace pmill\AwsCognito;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Jose\Factory\JWKFactory;
use Jose\Loader;
use Jose\Object\DownloadedJWKSet;
use pmill\AwsCognito\Exception\TokenExpiryException;
use pmill\AwsCognito\Exception\TokenVerificationException;
use Psr\Cache\CacheItemPoolInterface;

class CognitoClient
{
    /**
     * @var string
     */
    protected $appClientId;

    /**
     * @var string
     */
    protected $appClientSecret;

    /**
     * @var CognitoIdentityProviderClient
     */
    protected $client;

    /**
     * @var DownloadedJWKSet
     */
    protected $jwtWebKeys;

    /**
     * @var string
     */
    protected $region;

    /**
     * @var string
     */
    protected $userPoolId;

    /**
     * CognitoClient constructor.
     *
     * @param CognitoIdentityProviderClient $client
     */
    public function __construct(CognitoIdentityProviderClient $client)
    {
        $this->client = $client;
    }

    /**
     * @param string $username
     * @param string $password
     *
     * @return array
     */
    public function authenticate($username, $password)
    {
        $response = $this->client->adminInitiateAuth([
            'AuthFlow' => 'ADMIN_NO_SRP_AUTH',
            'AuthParameters' => [
                'USERNAME' => $username,
                'PASSWORD' => $password,
                'SECRET_HASH' => $this->cognitoSecretHash($username),
            ],
            'ClientId' => $this->appClientId,
            'UserPoolId' => $this->userPoolId,
        ]);

        return (array)$response['AuthenticationResult'];
    }

    /**
     * @param string $accessToken
     * @param string $previousPassword
     * @param string $proposedPassword
     */
    public function changePassword($accessToken, $previousPassword, $proposedPassword)
    {
        $this->verifyAccessToken($accessToken);

        $this->client->changePassword([
            'AccessToken' => $accessToken,
            'PreviousPassword' => $previousPassword,
            'ProposedPassword' => $proposedPassword,
        ]);
    }

    /**
     * @param string $confirmationCode
     * @param string $username
     */
    public function confirmUserRegistration($confirmationCode, $username)
    {
        $this->client->confirmSignUp([
            'ClientId' => $this->appClientId,
            'ConfirmationCode' => $confirmationCode,
            'SecretHash' => $this->cognitoSecretHash($username),
            'Username' => $username,
        ]);
    }

    /**
     * @param string $accessToken
     */
    public function deleteUser($accessToken)
    {
        $this->verifyAccessToken($accessToken);

        $this->client->deleteUser([
            'AccessToken' => $accessToken,
        ]);
    }

    /**
     * @param CacheItemPoolInterface $cache
     */
    public function downloadJwtWebKeys(CacheItemPoolInterface $cache = null)
    {
        $url = sprintf(
            'https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json',
            $this->region,
            $this->userPoolId
        );

        $this->jwtWebKeys = JWKFactory::createFromJKU($url, false, $cache);
    }

    /**
     * @param string $username
     * @param string $password
     * @param array $attributes
     *
     * @return bool
     */
    public function registerUser($username, $password, array $attributes = [])
    {
        $userAttributes = [];
        foreach ($attributes as $key => $value) {
            $userAttributes[] = [
                'Name' => $key,
                'Value' => $value,
            ];
        }

        $response = $this->client->signUp([
            'ClientId' => $this->appClientId,
            'Password' => $password,
            'SecretHash' => $this->cognitoSecretHash($username),
            'UserAttributes' => $userAttributes,
            'Username' => $username,
        ]);

        return (bool) $response['UserConfirmed'];
    }

    /**
     * @param string $confirmationCode
     * @param string $username
     * @param string $proposedPassword
     */
    public function resetPassword($confirmationCode, $username, $proposedPassword)
    {
        $this->client->confirmForgotPassword([
            'ClientId' => $this->appClientId,
            'ConfirmationCode' => $confirmationCode,
            'Password' => $proposedPassword,
            'SecretHash' => $this->cognitoSecretHash($username),
            'Username' => $username,
        ]);
    }

    /**
     * @param string $username
     */
    public function resendRegistrationConfirmationCode($username)
    {
        $this->client->resendConfirmationCode([
            'ClientId' => $this->appClientId,
            'SecretHash' => $this->cognitoSecretHash($username),
            'Username' => $username,
        ]);
    }

    /**
     * @param string $username
     */
    public function sendForgottenPasswordRequest($username)
    {
        $this->client->forgotPassword([
            'ClientId' => $this->appClientId,
            'SecretHash' => $this->cognitoSecretHash($username),
            'Username' => $username,
        ]);
    }

    /**
     * @param string $appClientId
     */
    public function setAppClientId($appClientId)
    {
        $this->appClientId = $appClientId;
    }

    /**
     * @param string $appClientSecret
     */
    public function setAppClientSecret($appClientSecret)
    {
        $this->appClientSecret = $appClientSecret;
    }

    /**
     * @param CognitoIdentityProviderClient $client
     */
    public function setClient($client)
    {
        $this->client = $client;
    }

    /**
     * @param string $region
     */
    public function setRegion($region)
    {
        $this->region = $region;
    }

    /**
     * @param string $userPoolId
     */
    public function setUserPoolId($userPoolId)
    {
        $this->userPoolId = $userPoolId;
    }

    /**
     * @param string $accessToken
     *
     * @throws TokenExpiryException
     * @throws TokenVerificationException
     */
    public function verifyAccessToken($accessToken)
    {
        $signatureIndex = null;
        $loader = new Loader();
        $jwt = $loader->loadAndVerifySignatureUsingKeySet($accessToken, $this->jwtWebKeys, ['RS256'], $signatureIndex);
        /** @var array $jwtPayload */
        $jwtPayload = $jwt->getPayload();

        $expectedIss = sprintf('https://cognito-idp.%s.amazonaws.com/%s', $this->region, $this->userPoolId);
        if ($jwtPayload['iss'] !== $expectedIss) {
            throw new TokenVerificationException('invalid iss');
        }

        if ($jwtPayload['token_use'] !== 'access') {
            throw new TokenVerificationException('invalid token_use');
        }

        if ($jwtPayload['exp'] < time()) {
            throw new TokenExpiryException('invalid exp');
        }
    }

    /**
     * @param string $username
     *
     * @return string
     */
    protected function cognitoSecretHash($username)
    {
        return $this->hash($username . $this->appClientId);
    }

    /**
     * @param string $message
     *
     * @return string
     */
    protected function hash($message)
    {
        $hash = hash_hmac(
            'sha256',
            $message,
            $this->appClientSecret,
            true
        );

        return base64_encode($hash);
    }
}
