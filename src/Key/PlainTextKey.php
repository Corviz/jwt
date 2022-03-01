<?php

namespace Corviz\Jwt\Key;

class PlainTextKey implements Key
{
    /**
     * @var string
     */
    private string $key;

    /**
     * @return string
     */
    public function toString(): string
    {
        return $this->key;
    }

    /**
     * @param string $key
     */
    public function __construct(string $key)
    {
        $this->key = $key;
    }
}
