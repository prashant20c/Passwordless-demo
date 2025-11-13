<?php

namespace App\Routes;

use App;
use App\Lib\Crypto;
use App\Lib\Jwt;
use App\Lib\Response;
use App\Lib\Validator;

function handle_device_link_start(array $payload): void
{
    Validator::require($payload, ['email']);
    Validator::email($payload['email']);

    $user = App\db_find_user_by_email($payload['email']);
    if (!$user) {
        Response::error('User not found', 404);
    }

    $ttl = (int) env('LINK_CODE_TTL_SECONDS', 600);
    if ($ttl <= 0) {
        $ttl = 600;
    }

    $linkCode = Crypto::generateLinkCode(6);
    $expiresAt = gmdate('c', time() + $ttl);

    App\db_update_user($user['id'], [
        'link_code' => $linkCode,
        'link_code_expires_at' => $expiresAt
    ]);

    Response::json([
        'link_code' => $linkCode,
        'expires_at' => $expiresAt,
        'ttl_seconds' => $ttl
    ]);
}

function handle_device_link_complete(array $payload): void
{
    Validator::require($payload, ['email', 'device_name', 'link_code', 'public_key']);
    Validator::email($payload['email']);

    $user = App\db_find_user_by_email($payload['email']);
    if (!$user) {
        Response::error('Invalid or expired link code', 400);
    }

    $providedCode = preg_replace('/\D+/', '', (string) $payload['link_code']) ?? '';
    $storedCode = $user['link_code'] ?? null;

    if (!$storedCode || $providedCode !== $storedCode) {
        Response::error('Invalid or expired link code', 400);
    }

    $expiresAt = isset($user['link_code_expires_at']) ? strtotime($user['link_code_expires_at']) : null;
    if (!$expiresAt || $expiresAt < time()) {
        Response::error('Invalid or expired link code', 400);
    }

    $deviceData = [
        'user_id' => $user['id'],
        'device_name' => $payload['device_name'],
        'public_key' => $payload['public_key']
    ];

    $existingDevice = App\db_find_device_by_user_and_name($user['id'], $payload['device_name']);
    if ($existingDevice) {
        $device = App\db_update_device($existingDevice['id'], $deviceData);
    } else {
        $device = App\db_create_device($deviceData);
    }

    App\db_update_user($user['id'], [
        'link_code' => null,
        'link_code_expires_at' => null
    ]);

    Response::json([
        'device_id' => $device['id'],
        'status' => 'linked'
    ]);
}

function handle_device_pending(string $email): void
{
    Validator::email($email);
    $user = App\db_find_user_by_email($email);
    if (!$user) {
        Response::json(['logins' => []]);
    }

    $timeout = (int) env('LOGIN_TIMEOUT_SECONDS', 60);
    $pending = App\db_get_pending_logins_by_user($user['id']);
    $valid = [];
    foreach ($pending as $login) {
        if (strtotime($login['created_at']) < time() - $timeout) {
            App\db_update_login($login['id'], ['status' => 'EXPIRED']);
            continue;
        }
        $valid[] = $login;
    }

    $timeout = (int) env('LOGIN_TIMEOUT_SECONDS', 60);
    $logins = array_map(function ($login) use ($timeout) {
        $expiresAt = strtotime($login['created_at']) + $timeout;
        return [
            'login_id' => $login['login_id'],
            'challenge' => $login['challenge'],
            'created_at' => $login['created_at'],
            'expires_at' => gmdate('c', $expiresAt)
        ];
    }, $valid);

    Response::json(['logins' => $logins]);
}

function handle_device_approve(array $payload): void
{
    Validator::require($payload, ['login_id', 'signature']);

    $login = App\db_find_login_by_login_id($payload['login_id']);
    if (!$login) {
        Response::error('Login not found', 404);
    }

    $timeout = (int) env('LOGIN_TIMEOUT_SECONDS', 60);
    if ($login['status'] !== 'PENDING' || strtotime($login['created_at']) < time() - $timeout) {
        Response::error('Login already processed or expired', 400);
    }

    $user = App\db_find_user_by_id($login['user_id']);
    if (!$user) {
        Response::error('User not found', 404);
    }

    $devices = App\db_get_devices_by_user($user['id']);
    if (empty($devices)) {
        Response::error('No linked device found', 400);
    }

    $verified = false;
    $matchedDeviceId = null;
    foreach ($devices as $device) {
        if (Crypto::verifyEd25519($device['public_key'], $login['challenge'], $payload['signature'])) {
            $verified = true;
            $matchedDeviceId = $device['id'];
            break;
        }
    }

    if (!$verified) {
        Response::error('Invalid signature', 400);
    }

    $token = Jwt::issue([
        'sub' => $user['id'],
        'exp' => time() + 600
    ]);

    App\db_update_login($login['id'], [
        'status' => 'APPROVED',
        'token' => $token,
        'approved_at' => gmdate('c'),
        'device_id' => $matchedDeviceId
    ]);

    Response::json(['ok' => true]);
}

function handle_device_reject(array $payload): void
{
    Validator::require($payload, ['login_id', 'device_id']);

    $login = App\db_find_login_by_login_id($payload['login_id']);
    if (!$login) {
        Response::error('Login not found', 404);
    }

    if (($login['status'] ?? 'PENDING') !== 'PENDING') {
        Response::error('Login already processed', 400);
    }

    $deviceId = (int) $payload['device_id'];
    $device = App\db_find_device_by_id($deviceId);
    if (!$device || $device['user_id'] !== $login['user_id']) {
        Response::error('Device does not match login', 403);
    }

    App\db_update_login($login['id'], [
        'status' => 'REJECTED',
        'rejected_at' => gmdate('c'),
        'device_id' => $deviceId
    ]);

    Response::json(['status' => 'REJECTED']);
}

function handle_device_sessions_end(array $payload): void
{
    Validator::require($payload, ['device_id', 'email']);
    Validator::email($payload['email']);

    $user = App\db_find_user_by_email($payload['email']);
    if (!$user) {
        Response::error('User not found', 404);
    }

    $deviceId = (int) $payload['device_id'];
    $device = App\db_find_device_by_id($deviceId);
    if (!$device || $device['user_id'] !== $user['id']) {
        Response::error('Device mismatch', 403);
    }

    $activeSessions = App\db_get_logins([
        'user_id' => $user['id'],
        'status' => 'APPROVED'
    ]);

    $updated = 0;
    foreach ($activeSessions as $session) {
        App\db_update_login($session['id'], [
            'status' => 'ENDED',
            'ended_at' => gmdate('c'),
            'device_id' => $deviceId
        ]);
        $updated++;
    }

    Response::json([
        'status' => 'ENDED',
        'ended_sessions' => $updated,
        'message' => 'Requested active sessions to be ended (TODO: replace with real session store).'
    ]);
}
