<?php

namespace App\Lib;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class Jwt
{
    public static function issue(array $claims): string
    {
        $payload = array_merge([
            'iat' => time(),
        ], $claims);

        return JWT::encode($payload, env('JWT_SECRET', 'dev_secret_change_me'), 'HS256');
    }

    public static function decode(string $token): array
    {
        return (array) JWT::decode($token, new Key(env('JWT_SECRET', 'dev_secret_change_me'), 'HS256'));
    }
}
