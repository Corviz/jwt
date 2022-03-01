<?php

namespace Corviz\Jwt\Signator;

use Corviz\Jwt\Jwt;

abstract class Signator
{
    /**
     * @return string
     */
    abstract public function algorithm() : string;

    /**
     * @param string $header
     * @param string $payload
     * @param string $key
     *
     * @return mixed
     */
    abstract public function sign(string $header, string $payload, string $key);
}
