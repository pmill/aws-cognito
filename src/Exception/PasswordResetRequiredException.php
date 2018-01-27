<?php
namespace pmill\AwsCognito\Exception;

use Throwable;

class PasswordResetRequiredException extends \Exception
{
    /**
     * PasswordResetRequiredException constructor.
     * @param Throwable|null $previous
     */
    public function __construct(Throwable $previous = null)
    {
        parent::__construct(get_class(), 0, $previous);
    }
}
