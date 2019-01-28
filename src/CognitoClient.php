<?php
namespace pmill\AwsCognito;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Exception;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Converter\StandardConverter;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use pmill\AwsCognito\Exception\ChallengeException;
use pmill\AwsCognito\Exception\CognitoResponseException;
use pmill\AwsCognito\Exception\TokenExpiryException;
use pmill\AwsCognito\Exception\TokenVerificationException;

class CognitoClient
{
    const CHALLENGE_NEW_PASSWORD_REQUIRED = 'NEW_PASSWORD_REQUIRED';

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
     * @var JWKSet
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
     * @throws ChallengeException
     * @throws Exception
     */
    public function authenticate($username, $password)
    {
        try {
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

            return $this->handleAuthenticateResponse($response->toArray());
        } catch (CognitoIdentityProviderException $e) {
            throw CognitoResponseException::createFromCognitoException($e);
        }
    }

    /**
     * @param string $challengeName
     * @param array $challengeResponses
     * @param string $session
     *
     * @return array
     * @throws ChallengeException
     * @throws Exception
     */
    public function respondToAuthChallenge($challengeName, array $challengeResponses, $session)
    {
        try {
            $response = $this->client->respondToAuthChallenge([
                'ChallengeName' => $challengeName,
                'ChallengeResponses' => $challengeResponses,
                'ClientId' => $this->appClientId,
                'Session' => $session,
            ]);

            return $this->handleAuthenticateResponse($response->toArray());
        } catch (CognitoIdentityProviderException $e) {
            throw CognitoResponseException::createFromCognitoException($e);
        }
    }

    /**
     * @param string $username
     * @param string $newPassword
     * @param string $session
     * @return array
     * @throws ChallengeException
     * @throws Exception
     */
    public function respondToNewPasswordRequiredChallenge($username, $newPassword, $session)
    {
        return $this->respondToAuthChallenge(
            self::CHALLENGE_NEW_PASSWORD_REQUIRED,
            [
                'NEW_PASSWORD' => $newPassword,
                'USERNAME' => $username,
                'SECRET_HASH' => $this->cognitoSecretHash($username),
            ],
            $session
        );
    }

    /**
     * @param string $username
     * @param string $refreshToken
     * @return string
     * @throws Exception
     */
    public function refreshAuthentication($username, $refreshToken)
    {
        try {
            $response = $this->client->adminInitiateAuth([
                'AuthFlow' => 'REFRESH_TOKEN_AUTH',
                'AuthParameters' => [
                    'USERNAME' => $username,
                    'REFRESH_TOKEN' => $refreshToken,
                    'SECRET_HASH' => $this->cognitoSecretHash($username),
                ],
                'ClientId' => $this->appClientId,
                'UserPoolId' => $this->userPoolId,
            ])->toArray();

            return $response['AuthenticationResult'];
        } catch (CognitoIdentityProviderException $e) {
            throw CognitoResponseException::createFromCognitoException($e);
        }
    }

    /**
     * @param string $accessToken
     * @param string $previousPassword
     * @param string $proposedPassword
     * @throws Exception
     * @throws TokenExpiryException
     * @throws TokenVerificationException
     */
    public function changePassword($accessToken, $previousPassword, $proposedPassword)
    {
        $this->verifyAccessToken($accessToken);

        try {
            $this->client->changePassword([
                'AccessToken' => $accessToken,
                'PreviousPassword' => $previousPassword,
                'ProposedPassword' => $proposedPassword,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            throw CognitoResponseException::createFromCognitoException($e);
        }
    }

    /**
     * @param string $confirmationCode
     * @param string $username
     * @throws Exception
     */
    public function confirmUserRegistration($confirmationCode, $username)
    {
        try {
            $this->client->confirmSignUp([
                'ClientId' => $this->appClientId,
                'ConfirmationCode' => $confirmationCode,
                'SecretHash' => $this->cognitoSecretHash($username),
                'Username' => $username,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            throw CognitoResponseException::createFromCognitoException($e);
        }
    }

    /*
     * @param string $username
     * @return AwsResult
     * @throws UserNotFoundException
     * @throws CognitoResponseException
     */
    public function getUser($username)
    {
        try {
            $response = $this->client->adminGetUser([
                'Username' => $username,
                'UserPoolId' => $this->userPoolId,
            ]);
            return $response;
        } catch (Exception $e) {
            throw CognitoResponseException::createFromCognitoException($e);
        }
    }

    /**
     * @param string $accessToken
     * @throws Exception
     * @throws TokenExpiryException
     * @throws TokenVerificationException
     */
    public function deleteUser($accessToken)
    {
        $this->verifyAccessToken($accessToken);

        try {
            $this->client->deleteUser([
                'AccessToken' => $accessToken,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            throw CognitoResponseException::createFromCognitoException($e);
        }
    }

    /**
     * @param string $username
     * @param string $groupName
     * @throws Exception
     */
    public function addUserToGroup($username, $groupName) {
        try {
            $this->client->adminAddUserToGroup([
                'UserPoolId' => $this->userPoolId,
                'Username' => $username,
                "GroupName" => $groupName
            ]);
        } catch (CognitoIdentityProviderException $e) {
            throw CognitoResponseException::createFromCognitoException($e);
        }
    }

    /**
     * @param $username
     * @param array $attributes
     * @throws Exception
     */
    public function updateUserAttributes($username, array $attributes = [])
    {
        $userAttributes = $this->buildAttributesArray($attributes);

        try {
            $this->client->adminUpdateUserAttributes([
                'Username' => $username,
                'UserPoolId' => $this->userPoolId,
                'UserAttributes' => $userAttributes,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            throw CognitoResponseException::createFromCognitoException($e);
        }
    }

    /**
     * @return JWKSet
     */
    public function getJwtWebKeys()
    {
        if (!$this->jwtWebKeys) {
            $json = $this->downloadJwtWebKeys();
            $this->jwtWebKeys = JWKSet::createFromJson($json);
        }

        return $this->jwtWebKeys;
    }

    /**
     * @param JWKSet $jwtWebKeys
     */
    public function setJwtWebKeys(JWKSet $jwtWebKeys)
    {
        $this->jwtWebKeys = $jwtWebKeys;
    }

    /**
     * @return string
     */
    protected function downloadJwtWebKeys()
    {
        $url = sprintf(
            'https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json',
            $this->region,
            $this->userPoolId
        );

        return file_get_contents($url);
    }

    /**
     * @param string $username
     * @param string $password
     * @param array $attributes
     * @return string
     * @throws Exception
     */
    public function registerUser($username, $password, array $attributes = [])
    {
        $userAttributes = $this->buildAttributesArray($attributes);

        try {
            $response = $this->client->signUp([
                'ClientId' => $this->appClientId,
                'Password' => $password,
                'SecretHash' => $this->cognitoSecretHash($username),
                'UserAttributes' => $userAttributes,
                'Username' => $username,
            ]);

            return $response['UserSub'];
        } catch (CognitoIdentityProviderException $e) {
            throw CognitoResponseException::createFromCognitoException($e);
        }
    }

    /**
     * @param string $confirmationCode
     * @param string $username
     * @param string $proposedPassword
     * @throws Exception
     */
    public function resetPassword($confirmationCode, $username, $proposedPassword)
    {
        try {
            $this->client->confirmForgotPassword([
                'ClientId' => $this->appClientId,
                'ConfirmationCode' => $confirmationCode,
                'Password' => $proposedPassword,
                'SecretHash' => $this->cognitoSecretHash($username),
                'Username' => $username,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            throw CognitoResponseException::createFromCognitoException($e);
        }
    }

    /**
     * @param string $username
     * @throws Exception
     */
    public function resendRegistrationConfirmationCode($username)
    {
        try {
            $this->client->resendConfirmationCode([
                'ClientId' => $this->appClientId,
                'SecretHash' => $this->cognitoSecretHash($username),
                'Username' => $username,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            throw CognitoResponseException::createFromCognitoException($e);
        }
    }

    /**
     * @param string $username
     * @throws Exception
     */
    public function sendForgottenPasswordRequest($username)
    {
        try {
            $this->client->forgotPassword([
                'ClientId' => $this->appClientId,
                'SecretHash' => $this->cognitoSecretHash($username),
                'Username' => $username,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            throw CognitoResponseException::createFromCognitoException($e);
        }
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
     * @return array
     * @throws TokenVerificationException
     */
    public function decodeAccessToken($accessToken)
    {
        $algorithmManager = AlgorithmManager::create([
            new RS256(),
        ]);

        $serializerManager = new CompactSerializer(new StandardConverter());

        $jws = $serializerManager->unserialize($accessToken);
        $jwsVerifier = new JWSVerifier(
            $algorithmManager
        );

        $keySet = $this->getJwtWebKeys();
        if (!$jwsVerifier->verifyWithKeySet($jws, $keySet, 0)) {
            throw new TokenVerificationException('could not verify token');
        }

        return json_decode($jws->getPayload(), true);
    }

    /**
     * Verifies the given access token and returns the username
     *
     * @param string $accessToken
     *
     * @throws TokenExpiryException
     * @throws TokenVerificationException
     *
     * @return string
     */
    public function verifyAccessToken($accessToken)
    {
        $jwtPayload = $this->decodeAccessToken($accessToken);

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

        return $jwtPayload['username'];
    }

    /**
     * @param string $username
     *
     * @return string
     */
    public function cognitoSecretHash($username)
    {
        return $this->hash($username . $this->appClientId);
    }

    /**
     * @param $username
     *
     * @return \Aws\Result
     * @throws Exception
     */
    public function getGroupsForUsername($username)
    {
        try {
            return $this->client->adminListGroupsForUser([
                'UserPoolId' => $this->userPoolId,
                'Username'   => $username
            ]);
        } catch (Exception $e) {
            throw CognitoResponseException::createFromCognitoException($e);
        }

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

    /**
     * @param array $response
     * @return array
     * @throws ChallengeException
     * @throws Exception
     */
    protected function handleAuthenticateResponse(array $response)
    {
        if (isset($response['AuthenticationResult'])) {
            return $response['AuthenticationResult'];
        }

        if (isset($response['ChallengeName'])) {
            throw ChallengeException::createFromAuthenticateResponse($response);
        }

        throw new Exception('Could not handle AdminInitiateAuth response');
    }

    /**
     * @param array $attributes
     * @return array
     */
    private function buildAttributesArray(array $attributes): array
    {
        $userAttributes = [];
        foreach ($attributes as $key => $value) {
            $userAttributes[] = [
                'Name' => (string)$key,
                'Value' => (string)$value,
            ];
        }
        return $userAttributes;
    }
}
