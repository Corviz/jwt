<?php

namespace Corviz\Jwt\Signer\Hmac\Sha;

use Corviz\Jwt\Signer\Hmac\HmacSigner;

class Sha384Signer extends HmacSigner
{
    protected string $hmacAlg = 'sha384';

    /**
     * @inheritDoc
     */
    public function algorithm(): string
    {
        return 'HS384';
    }
}