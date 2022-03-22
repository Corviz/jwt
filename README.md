# JWT

![JWT Logo](https://jwt.io/img/logo-asset.svg)

## How to install

```
composer require corviz/jwt
```

## Provided signers

<table>
    <tr>
        <th>Algorithm</th>
        <th>Version</th>
    </tr>
    <tr>
        <td>HS256</td>
        <td>1.0</td>
    </tr>
    <tr>
        <td>HS256</td>
        <td>1.0</td>
    </tr>
    <tr>
        <td>HS384</td>
        <td>1.0</td>
    </tr>
    <tr>
        <td>HS512</td>
        <td>1.0</td>
    </tr>
</table>

## Provided claim validators
<table>
    <tr>
        <th>Claim</th>
        <th>Version</th>
    </tr>
    <tr>
        <td>exp</td>
        <td>1.0</td>
    </tr>
    <tr>
        <td>nbf</td>
        <td>1.0</td>
    </tr>
</table>

## Basic Usage

### Generating token
```php
<?php

use Corviz\Jwt\Token;
use Corviz\Jwt\SignerFactory;

$token = Token::create()
            ->with('exp', strtotime('+ 1 hour')) //Expires in one hour
            ->withSigner(SignerFactory::build('HS256')) //HS256 signer is provided by default. This could be omitted
            ->sign($mySecret)
            ->toString();
```

### Validating and reading values from a token
```php
<?php

use Corviz\Jwt\Token;

$token = Token::fromString('xxxx.yyyyy.zzzzz');

$isValid = $token->validate($mySecret);

if ($isValid) {
    $payload = $token->getPayload();
    $headers = $token->getHeaders();
}
```

### Validating your private claims

First you have to create your validator

```php
use \Corviz\Jwt\Validator\Validator;

class MyClaimValidator extends Validator {
    /**
     * @return string
     */
    public function validates() : string
    {
        return 'my-claim'; //this will validate value inside 'my-claim', when set
    }
    
    /**
     * @param mixed $value
     * @return bool
     */
    public function validate(mixed $value) : bool
    {
        // this claim must contain value 'a', 'b' or 'c'
        $valid = in_array($value, ['a', 'b', 'c']);
        
        return $valid;
    }
}
```

Then all you have to do is assign your validator before running *validate()* method
```php
<?php

use Corviz\Jwt\Token;

$token = Token::fromString('xxxx.yyyyy.zzzzz')
            ->assignValidator(new MyClaimValidator());

$isValid = $token->validate($mySecret);

if ($isValid) {
    $myClaim = $payload = $token->getPayload('my-claim');
}
```