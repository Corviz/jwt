<?php

namespace Corviz\Jwt\Key;

interface Key
{
    /**
     * @return string
     */
    public function toString() : string;
}