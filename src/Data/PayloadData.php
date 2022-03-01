<?php

namespace Corviz\Jwt\Data;

use Corviz\Jwt\Data\Validators\ExpValidator;
use Corviz\Jwt\Data\Validators\NbfValidator;

class PayloadData extends Data
{
    /**
     * @link https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1
     */
    public const CLAIMS = [
        'iss', //Issuer
        'sub', //Subject
        'aud', //Audience
        'exp', //Expiration Time
        'nbf', //Not Before
        'iat', //Issued At
        'jti', //Jwt ID
    ];

    public function __construct()
    {
        $this->assignValidator('exp', new ExpValidator());
        $this->assignValidator('nbf', new NbfValidator());
    }
}