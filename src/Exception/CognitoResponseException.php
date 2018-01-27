<?php
namespace pmill\AwsCognito\Exception;

use Throwable;

class CognitoResponseException extends \Exception
{
    /**
     * CognitoResponseException constructor.
     * @param Throwable|null $previous
     */
    public function __construct(Throwable $previous = null)
    {
        parent::__construct(get_class(), 0, $previous);
    }
}
