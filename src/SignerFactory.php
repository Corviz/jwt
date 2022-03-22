<?php

namespace Corviz\Jwt;

use Corviz\Jwt\Signer\Hmac\Sha;
use Corviz\Jwt\Signer\Signer;
use Exception;

abstract class SignerFactory
{
    /**
     * @var string[]
     */
    private static array $algMap = [
        'HS256' => Sha\Sha256Signer::class,
        'HS384' => Sha\Sha384Signer::class,
        'HS512' => Sha\Sha512Signer::class,
    ];

    /**
     * @param string $alg
     * @param string $className
     * @return void
     */
    public static function assign(string $alg, string $className)
    {
        self::$algMap[$alg] = $className;
    }

    /**
     * @param string $alg
     * @return Signer
     * @throws Exception
     */
    public static function build(string $alg) : Signer
    {
        if (!isset(self::$algMap[$alg])) {
            throw new Exception("Unsupported algorith: $alg");
        }

        $className = self::$algMap[$alg];
        return new $className;
    }
}