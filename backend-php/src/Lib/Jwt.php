<?php

namespace App\Lib;

use Firebase\JWT\JWT as FirebaseJWT;
use Firebase\JWT\Key;

class Jwt
{
    public static function issue(array $claims): string
    {
        $payload = array_merge([
            'iat' => time(),
        ], $claims);

        return FirebaseJWT::encode($payload, env('JWT_SECRET', 'dev_secret_change_me'), 'HS256');
    }

    public static function decode(string $token): array
    {
        return (array) FirebaseJWT::decode($token, new Key(env('JWT_SECRET', 'dev_secret_change_me'), 'HS256'));
    }
}
