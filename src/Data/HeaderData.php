<?php

namespace Corviz\Jwt\Data;

class HeaderData extends Data
{
    /**
     * @link https://www.rfc-editor.org/rfc/rfc7519.html#section-5
     */
    public const CLAIMS = [
        'typ', //Type
        'cty', //Content Type
        'alg', //Algorithm
    ];

    /**
     *
     */
    public function __construct()
    {
        $this->set('typ', 'JWT');
    }
}
