<?php

namespace App\Routes;

use App;
use App\Lib\Crypto;
use App\Lib\Jwt;
use App\Lib\Response;
use App\Lib\Validator;

function handle_device_link(array $payload): void
{
    Validator::require($payload, ['email', 'password', 'device_name', 'public_key']);
    Validator::email($payload['email']);

    $user = App\db_find_user_by_email($payload['email']);
    if (!$user || !password_verify($payload['password'], $user['password_hash'])) {
        Response::error('Invalid credentials', 401);
    }

    $device = App\db_create_device([
        'user_id' => $user['id'],
        'device_name' => $payload['device_name'],
        'public_key' => $payload['public_key']
    ]);

    Response::json(['ok' => true, 'device_id' => $device['id']]);
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

    $logins = array_map(function ($login) {
        return [
            'login_id' => $login['login_id'],
            'challenge' => $login['challenge'],
            'created_at' => $login['created_at']
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
    foreach ($devices as $device) {
        if (Crypto::verifyEd25519($device['public_key'], $login['challenge'], $payload['signature'])) {
            $verified = true;
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
        'approved_at' => gmdate('c')
    ]);

    Response::json(['ok' => true]);
}
