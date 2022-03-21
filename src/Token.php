<?php

namespace Corviz\Jwt;

use Corviz\Jwt\Signer\Hmac\Sha\Sha256Signer;
use Corviz\Jwt\Signer\Signer;

class Token
{
    /**
     *
     */
    public const DEFAULT_SIGNER = Sha256Signer::class;

    /**
     * @var array
     */
    private array $headers = [];

    /**
     * @var array
     */
    private array $payload = [];

    /**
     * @var Signer
     */
    private Signer $signer;

    /**
     * @return static
     */
    public static function create()
    {
        return new static();
    }

    /**
     * @param string $index
     * @return $this
     */
    public function remove(string $index)
    {
        unset($this->payload[$index]);
        return $this;
    }

    /**
     * @param string $index
     * @return $this
     */
    public function removeHeader(string $index)
    {
        unset($this->headers[$index]);
        return $this;
    }

    /**
     * @param Signer $signer
     * @return $this
     */
    public function signer(Signer $signer)
    {
        $this->signer = $signer;
        return $this->withHeader('alg', $signer->algorithm());
    }

    /**
     * @return string
     */
    public function toString()
    {
        $header = base64_encode(json_encode($this->headers));
        $payload = base64_encode(json_encode($this->payload));
        $signature = base64_encode($this->signer->sign($header, $payload));

        return "$header.$payload.$signature";
    }

    /**
     * @param string $index
     * @param mixed $value
     * @return $this
     */
    public function with(string $index, mixed $value)
    {
        $this->payload[$index] = $value;
        return $this;
    }

    /**
     * @param string $index
     * @param mixed $value
     * @return $this
     */
    public function withHeader(string $index, mixed $value)
    {
        $this->headers[$index] = $value;
        return $this;
    }

    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->withHeader('typ', 'JWT')
            ->signer(self::getDefaultSigner());
    }

    /**
     * @return Signer
     */
    private static function getDefaultSigner() : Signer
    {
        $signer = self::DEFAULT_SIGNER;

        return new $signer;
    }
}
