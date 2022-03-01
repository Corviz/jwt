<?php

namespace Corviz\Jwt\Signator\Hmac\Sha;

use Corviz\Jwt\Signator\Hmac\HmacSignator;

class Sha256Signator extends HmacSignator
{
    /**
     * @var string
     */
    protected string $hmacAlg = 'sha256';

    /**
     * @inheritDoc
     */
    public function algorithm(): string
    {
        return 'HS256';
    }
}
