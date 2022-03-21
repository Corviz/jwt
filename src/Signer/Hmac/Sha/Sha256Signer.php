<?php

namespace Corviz\Jwt\Signer\Hmac\Sha;

use Corviz\Jwt\Signer\Hmac\HmacSigner;

class Sha256Signer extends HmacSigner
{
    protected string $hmacAlg = 'sha256';

    /**
     * @inheritDoc
     */
    public function algorithm(): string
    {
        return 'HS256';
    }
}