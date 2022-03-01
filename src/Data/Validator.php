<?php

namespace Corviz\Jwt\Data;

interface Validator
{
    /**
     * Returns TRUE when provided $value is valid, FALSE otherwise.
     *
     * @return bool
     */
    public function validate($value) : bool;
}
