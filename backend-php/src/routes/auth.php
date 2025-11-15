<?php

namespace App\Routes;

use App;
use App\Lib\ClientLabel;
use App\Lib\Crypto;
use App\Lib\Jwt;
use App\Lib\Response;
use App\Lib\Validator;

function handle_register(array $payload): void
{
    Validator::require($payload, ['full_name', 'email']);
    Validator::email($payload['email']);

    if (App\db_find_user_by_email($payload['email'])) {
        Response::error('Email already registered', 409);
    }

    $user = App\db_create_user([
        'full_name' => $payload['full_name'],
        'email' => $payload['email'],
        'link_code' => null,
        'link_code_expires_at' => null
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
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $ipAddress = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $clientLabel = ClientLabel::describe($userAgent);

    $challenge = Crypto::generateChallenge();
    $record = App\db_create_login([
        'login_id' => $loginId,
        'user_id' => $user['id'],
        'challenge' => $challenge,
        'status' => 'PENDING',
        'created_at' => gmdate('c'),
        'user_agent' => $userAgent,
        'ip_address' => $ipAddress,
        'client_label' => $clientLabel,
        'session_id' => $loginId
    ]);

    Response::json([
        'login_id' => $record['login_id'] ?? $loginId,
        'ip_address' => $ipAddress,
        'client_label' => $clientLabel
    ]);
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
    [$user, $claims] = authenticate_user($authHeader);

    Response::json([
        'id' => $user['id'],
        'full_name' => $user['full_name'],
        'email' => $user['email'],
        'session_id' => $claims['sid'] ?? null
    ]);
}

function handle_me_sessions(?string $authHeader): void
{
    [$user] = authenticate_user($authHeader);
    $sessions = App\db_get_sessions([
        'user_id' => $user['id'],
        'status' => 'active',
        '_sort' => 'created_at',
        '_order' => 'desc'
    ]);

    $payload = array_map(function ($session) {
        return [
            'session_id' => $session['session_id'],
            'client_label' => $session['client_label'] ?? ClientLabel::describe($session['user_agent'] ?? ''),
            'ip_address' => $session['ip_address'] ?? null,
            'created_at' => $session['created_at'],
            'last_seen_at' => $session['last_seen_at'] ?? null,
            'status' => $session['status']
        ];
    }, $sessions);

    Response::json(['sessions' => $payload]);
}

function handle_me_devices(?string $authHeader): void
{
    [$user] = authenticate_user($authHeader);
    $devices = App\db_get_devices_by_user($user['id']);
    $formatted = array_map(function ($device) {
        return [
            'id' => $device['id'],
            'device_name' => $device['device_name'],
            'linked_at' => $device['linked_at'] ?? null,
            'status' => 'active'
        ];
    }, $devices);

    Response::json(['devices' => $formatted]);
}

function handle_me_logout(?string $authHeader): void
{
    [$user, $claims] = authenticate_user($authHeader);
    $sessionId = $claims['sid'] ?? null;
    if (!$sessionId) {
        Response::json(['status' => 'ok']);
    }

    $session = App\db_find_session_by_session_id($sessionId);
    if ($session && (int) $session['user_id'] === (int) $user['id']) {
        App\db_update_session($session['id'], [
            'status' => 'revoked',
            'revoked_at' => gmdate('c'),
            'last_seen_at' => gmdate('c')
        ]);

        if (!empty($session['login_id'])) {
            $login = App\db_find_login_by_login_id($session['login_id']);
            if ($login) {
                App\db_update_login($login['id'], [
                    'status' => 'ENDED',
                    'ended_at' => gmdate('c')
                ]);
            }
        }
    }

    Response::json(['status' => 'revoked']);
}

function authenticate_user(?string $authHeader, bool $touchSession = true): array
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

    if ($touchSession && !empty($payload['sid'])) {
        $session = App\db_find_session_by_session_id($payload['sid']);
        if ($session && (int) $session['user_id'] === (int) $user['id']) {
            App\db_update_session($session['id'], ['last_seen_at' => gmdate('c')]);
        }
    }

    return [$user, $payload];
}
