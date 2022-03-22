<?php

namespace Corviz\Jwt\Validator;

class NbfValidator extends Validator
{

    /**
     * @inheritDoc
     */
    function validates(): string
    {
        return 'nbf';
    }

    /**
     * @inheritDoc
     */
    function validate(mixed $value): bool
    {
        return $value < time();
    }
}