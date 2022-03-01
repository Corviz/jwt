<?php

namespace Corviz\Jwt\Data\Validators;

use Corviz\Jwt\Data\Validator;

class NbfValidator implements Validator
{
    /**
     * @inheritDoc
     */
    public function validate($value): bool
    {
        return is_int($value) && time() >= $value;
    }
}