<?php

namespace Corviz\Jwt\Signer;

abstract class Signer
{
    /**
     * @var mixed
     */
    private mixed $secret;

    /**
     * @return mixed
     */
    public function getSecret(): mixed
    {
        return $this->secret;
    }

    /**
     * @param mixed $secret
     */
    public function setSecret(mixed $secret): void
    {
        $this->secret = $secret;
    }

    /**
     * @return string
     */
    abstract public function algorithm() : string;

    /**
     * @param string $header
     * @param string $payload
     * @param string $key
     *
     * @return mixed
     */
    abstract public function sign(string $header, string $payload);
}
