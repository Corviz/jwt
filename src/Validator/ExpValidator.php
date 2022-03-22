<?php

namespace Corviz\Jwt\Validator;

class ExpValidator extends Validator
{

    /**
     * @inheritDoc
     */
    function validates(): string
    {
        return 'exp';
    }

    /**
     * @inheritDoc
     */
    function validate(mixed $value): bool
    {
        return $value > time();
    }
}
