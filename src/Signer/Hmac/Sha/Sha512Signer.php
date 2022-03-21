<?php

namespace Corviz\Jwt\Signer\Hmac\Sha;

use Corviz\Jwt\Signer\Hmac\HmacSigner;

class Sha512Signer extends HmacSigner
{
    protected string $hmacAlg = 'sha512';

    /**
     * @inheritDoc
     */
    public function algorithm(): string
    {
        return 'HS512';
    }
}