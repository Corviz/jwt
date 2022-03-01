<?php

namespace Corviz\Jwt\Signator\Hmac\Sha;

use Corviz\Jwt\Signator\Hmac\HmacSignator;

class Sha512Signator extends HmacSignator
{
    /**
     * @var string
     */
    protected string $hmacAlg = 'sha512';

    /**
     * @inheritDoc
     */
    public function algorithm(): string
    {
        return 'HS512';
    }
}
