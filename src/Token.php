<?php

namespace Corviz\Jwt;

use Corviz\Jwt\Signer\Hmac\Sha\Sha256Signer;
use Corviz\Jwt\Signer\Signer;
use Corviz\Jwt\Validator\ExpValidator;
use Corviz\Jwt\Validator\NbfValidator;
use Corviz\Jwt\Validator\Validator;
use Exception;

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
     * @var string|null
     */
    private ?string $lastValidationIssue = null;

    /**
     * @var array
     */
    private array $payload = [];

    /**
     * @var string
     */
    private string $signature;

    /**
     * @var Signer
     */
    private Signer $signer;

    /**
     * @var array
     */
    private array $validators = [];

    /**
     * @var array
     */
    private array $headerValidators = [];

    /**
     * @return static
     */
    public static function create() : Token
    {
        return new static();
    }

    /**
     * @return Token
     * @throws Exception
     */
    public static function fromAuthorizationBearer() : Token
    {
       $authorizationHeader = null;

        if (isset($_SERVER['Authorization'])) {
            $authorizationHeader = trim($_SERVER['Authorization']);
        } else if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $authorizationHeader = trim($_SERVER['HTTP_AUTHORIZATION']);
        } else {
            $headers =  getallheaders();
            $headers = array_combine(
                array_map(
                    'ucwords',
                    array_keys($headers)
                ),
                array_values($headers)
            );

            if (isset($headers['Authorization'])) {
                $authorizationHeader = trim($headers['Authorization']);
            }
        }

        if (!$authorizationHeader) {
            throw new Exception('Authorization header is not set');
        }


        $matches = [];
        if (!preg_match('/Bearer\s((.*)\.(.*)\.(.*))/', $authorizationHeader, $matches)) {
            throw new Exception('Invalid "Authorization" header value');
        }

        return static::fromString($matches[1]);
    }

    /**
     * @param $param
     * @return Token
     * @throws Exception
     */
    public static function fromQueryString($param = 'token') : Token
    {
        $token = isset($_GET[$param]) ? $_GET[$param] : null;

        return static::fromString($token);
    }

    /**
     * @param string $token
     * @return Token
     * @throws Exception
     */
    public static function fromString(string $token) : Token
    {
        $parts = explode('.', $token);

        if (count($parts) != 3) {
            throw new Exception('Invalid token: JWT token must have 3 sections separated by "."');
        }

        $headers = json_decode(self::decodeSection($parts[0]), true) ?: [];
        $payload = json_decode(self::decodeSection($parts[1]), true) ?: [];
        $signature = self::decodeSection($parts[2]) ?: '';

        if (empty($headers['alg'])) {
            throw new Exception('"alg" JWT header must not be empty');
        }

        return static::create()
            ->setHeaders($headers)
            ->setPayload($payload)
            ->setSignature($signature)
            ->withSigner(SignerFactory::build($headers['alg']));
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
     * @param Validator $validator
     * @return $this
     */
    public function assignValidator(Validator $validator) : Token
    {
        $this->validators[$validator->validates()] = $validator;
        return $this;
    }

    /**
     * @param Validator $validator
     * @return $this
     */
    public function assignHeaderValidator(Validator $validator) : Token
    {
        $this->headerValidators[$validator->validates()] = $validator;
        return $this;
    }

    /**
     * @return string|null
     */
    public function getLastValidationIssue(): ?string
    {
        return $this->lastValidationIssue;
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
     * @param array $headers
     * @return $this
     */
    public function setHeaders(array $headers): Token
    {
        $this->headers = $headers;
        return $this;
    }

    /**
     * @param array $payload
     * @return $this
     */
    public function setPayload(array $payload): Token
    {
        $this->payload = $payload;
        return $this;
    }

    /**
     * @param string $signature
     * @return $this
     */
    public function setSignature(string $signature): Token
    {
        $this->signature = $signature;
        return $this;
    }

    /**
     * @param mixed $secret
     * @return $this
     */
    public function sign(mixed $secret) : Token
    {
        $this->signer->setSecret($secret);

        $this->signature = $this->signer->sign(
            self::encodeSection(json_encode($this->headers)),
            self::encodeSection(json_encode($this->payload))
        );

        return $this;
    }

    /**
     * @return string
     */
    public function toString() : string
    {
        $header = self::encodeSection(json_encode($this->headers));
        $payload = self::encodeSection(json_encode($this->payload));
        $signature = self::encodeSection($this->signature);

        return "$header.$payload.$signature";
    }

    /**
     * @param mixed $secret
     * @return bool
     */
    public function validate(mixed $secret) : bool
    {
        //Validate headers
        foreach ($this->headerValidators as $i => $validator) {
            /* @var $validator Validator */

            if (isset($this->headers[$i]) && !$validator->validate($this->headers[$i])) {
                $this->lastValidationIssue = "Header '$i' value is invalid.";
                return false;
            }
        }

        //Validate payload
        foreach ($this->validators as $i => $validator) {
            /* @var $validator Validator */

            if (isset($this->payload[$i]) && !$validator->validate($this->payload[$i])) {
                $this->lastValidationIssue = "Payload field '$i' value is invalid.";
                return false;
            }
        }

        //Validate signature
        $signer = clone $this->signer;
        $signer->setSecret($secret);

        $valid = $this->signature === $signer->sign(
                self::encodeSection(json_encode($this->headers)),
                self::encodeSection(json_encode($this->payload))
            );

        if (!$valid) {
            $this->lastValidationIssue = "Token signature is invalid.";
        }

        return $valid;
    }

    /**
     * @param string $index
     * @param mixed $value
     * @return $this
     */
    public function with(string $index, mixed $value) : Token
    {
        $this->payload[$index] = $value;
        return $this;
    }

    /**
     * @param string $index
     * @param mixed $value
     * @return $this
     */
    public function withHeader(string $index, mixed $value) : Token
    {
        $this->headers[$index] = $value;
        return $this;
    }

    /**
     * @param Signer $signer
     * @return $this
     */
    public function withSigner(Signer $signer) : Token
    {
        $this->signer = $signer;
        return $this->withHeader('alg', $signer->algorithm());
    }

    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->withHeader('typ', 'JWT')
            ->withSigner(self::getDefaultSigner())
            ->assignValidator(new NbfValidator())
            ->assignValidator(new ExpValidator());
    }

    /**
     * @return Signer
     */
    private static function getDefaultSigner() : Signer
    {
        $signer = self::DEFAULT_SIGNER;

        return new $signer;
    }

    /**
     * @param string $value
     * @return string
     */
    private static function encodeSection(string $value) : string
    {
        return str_replace(['/','+'],['_','-'], rtrim(base64_encode($value), '='));
    }

    /**
     * @param string $encoded
     * @return string
     */
    private static function decodeSection(string $encoded) : string
    {
        return base64_decode(str_replace(['_','-'], ['/','+'], $encoded));
    }
}
