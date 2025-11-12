<?php

namespace App\Routes;

use App;
use App\Lib\Crypto;
use App\Lib\Jwt;
use App\Lib\Response;
use App\Lib\Validator;

function handle_register(array $payload): void
{
    Validator::require($payload, ['full_name', 'email', 'password']);
    Validator::email($payload['email']);

    if (App\db_find_user_by_email($payload['email'])) {
        Response::error('Email already registered', 409);
    }

    $user = App\db_create_user([
        'full_name' => $payload['full_name'],
        'email' => $payload['email'],
        'password_hash' => password_hash($payload['password'], PASSWORD_DEFAULT)
    ]);

    Response::json(['ok' => true, 'user_id' => $user['id']]);
}

function handle_login_request(array $payload): void
{
    Validator::require($payload, ['email']);
    Validator::email($payload['email']);

    $user = App\db_find_user_by_email($payload['email']);
    if (!$user) {
        Response::error('User not found', 404);
    }

    $limit = (int) env('LOGIN_RATE_PER_MIN', 5);
    if ($limit > 0) {
        $since = gmdate('c', time() - 60);
        $recent = App\db_get_logins([
            'user_id' => $user['id'],
            'created_at_gte' => $since
        ]);
        if (count($recent) >= $limit) {
            Response::error('Too many login attempts. Please wait a moment.', 429);
        }
    }

    $loginId = bin2hex(random_bytes(16));
    $challenge = Crypto::generateChallenge();
    $record = App\db_create_login([
        'login_id' => $loginId,
        'user_id' => $user['id'],
        'challenge' => $challenge,
        'status' => 'PENDING',
        'created_at' => gmdate('c')
    ]);

    Response::json(['login_id' => $record['login_id'] ?? $loginId]);
}

function handle_login_status(string $loginId): void
{
    $login = App\db_find_login_by_login_id($loginId);
    if (!$login) {
        Response::error('Login not found', 404);
    }

    $timeout = (int) env('LOGIN_TIMEOUT_SECONDS', 60);
    if ($login['status'] === 'PENDING' && strtotime($login['created_at']) < time() - $timeout) {
        App\db_update_login($login['id'], ['status' => 'EXPIRED']);
        Response::json(['status' => 'EXPIRED']);
    }

    if ($login['status'] === 'APPROVED') {
        Response::json(['status' => 'APPROVED', 'token' => $login['token'] ?? null]);
    }

    Response::json(['status' => $login['status']]);
}

function handle_me(?string $authHeader): void
{
    if (!$authHeader || !preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
        Response::error('Unauthorized', 401);
    }

    try {
        $payload = Jwt::decode($matches[1]);
    } catch (\Throwable $e) {
        Response::error('Invalid token', 401);
    }

    $user = App\db_find_user_by_id($payload['sub'] ?? 0);
    if (!$user) {
        Response::error('User not found', 404);
    }

    Response::json([
        'id' => $user['id'],
        'full_name' => $user['full_name'],
        'email' => $user['email']
    ]);
}
