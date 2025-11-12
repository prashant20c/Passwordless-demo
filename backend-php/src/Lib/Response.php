<?php

namespace App\Lib;

class Response
{
    public static function json($data, int $status = 200): void
    {
        http_response_code($status);
        header('Content-Type: application/json');
        echo json_encode($data, JSON_UNESCAPED_SLASHES);
        exit;
    }

    public static function error(string $message, int $status = 400, array $extra = []): void
    {
        $payload = array_merge(['message' => $message], $extra);
        self::json($payload, $status);
    }
}
