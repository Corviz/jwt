<?php

namespace Corviz\Jwt\Validator;

abstract class Validator
{
    /**
     * Must return the validated field name;
     *
     * @return string
     */
    abstract function validates() : string;

    /**
     * Validates the field specified by validates().
     * Returns true when valid; false otherwise.
     *
     * @param mixed $value
     * @return bool
     */
    abstract function validate(mixed $value) : bool;
}