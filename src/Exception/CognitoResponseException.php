<?php
namespace pmill\AwsCognito\Exception;

use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Exception;
use Throwable;

class CognitoResponseException extends Exception
{
    /**
     * CognitoResponseException constructor.
     * @param Throwable|null $previous
     */
    public function __construct(Throwable $previous = null)
    {
        parent::__construct(get_class(), 0, $previous);
    }

    /**
     * @param CognitoIdentityProviderException $e
     * @return Exception
     */
    public static function createFromCognitoException(CognitoIdentityProviderException $e)
    {
        $errorClass = "pmill\\AwsCognito\\Exception\\" . $e->getAwsErrorCode();

        if (class_exists($errorClass)) {
            return new $errorClass($e);
        }

        return $e;
    }
}
