<?php

namespace Corviz\Jwt;

use Corviz\Jwt\Data\HeaderData;
use Corviz\Jwt\Data\PayloadData;
use Corviz\Jwt\Key\Key;
use Corviz\Jwt\Signator\Hmac\Sha\Sha256Signator;
use Corviz\Jwt\Signator\Signator;

class Jwt
{
    /**
     *
     */
    public const DEFAULT_SIGNATOR = Sha256Signator::class;

    /**
     * @var HeaderData
     */
    private HeaderData $header;

    /**
     * @var PayloadData
     */
    private PayloadData $payload;

    /**
     * @var Signator
     */
    private Signator $signator;

    /**
     * @var Key
     */
    private Key $key;

    /**
     * @param string $token
     * @param Jwt $jwt
     *
     * @return bool
     */
    public static function validate(string $token, Jwt $jwt) : bool
    {
        return $token === $jwt->toString()
            && $jwt->header->isValid()
            && $jwt->payload->isValid();
    }

    /**
     * @return HeaderData
     */
    public function header() : HeaderData
    {
        return $this->header;
    }

    /**
     * @return PayloadData
     */
    public function payload() : PayloadData
    {
        return $this->payload;
    }

    /**
     * Create a string formatted token.
     *
     * @return string
     */
    public function toString() : string
    {
        $header = base64_encode($this->header->jsonSerialize());
        $payload = base64_encode($this->payload->jsonSerialize());
        $signature = base64_encode($this->signator->sign($header, $payload, $this->key->toString()));

        return "$header.$payload.$signature";
    }

    /**
     * Jwt constructor.
     */
    public function __construct(
        Key $key,
        Signator $signator = null,
        HeaderData $header = null,
        PayloadData $payload = null
    ) {
        $defaultSignator = self::DEFAULT_SIGNATOR;

        $this->key = $key;
        $this->signator = $signator ?: new $defaultSignator;
        $this->header = $header ?: new HeaderData();
        $this->payload = $payload ?: new PayloadData();
    }
}