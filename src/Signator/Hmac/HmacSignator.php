<?php

namespace Corviz\Jwt\Signator\Hmac;

use Corviz\Jwt\Signator\Signator;

abstract class HmacSignator extends Signator
{
    /**
     * @var string
     */
    protected string $hmacAlg;

    /**
     * @param string $header
     * @param string $payload
     * @param string $key
     *
     * @return false|mixed|string
     */
    public function sign(string $header, string $payload, string $key)
    {
        return hash_hmac($this->hmacAlg, "$header.$payload", $key, true);
    }
}