<?php

namespace App;

use App\Lib\Response;

function db_request(string $method, string $resource, array $data = null, array $query = []): array
{
    $base = rtrim(env('JSON_SERVER_BASE', 'http://localhost:4000'), '/');
    $url = $base . '/' . ltrim($resource, '/');
    if (!empty($query)) {
        $url .= '?' . http_build_query($query);
    }

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    if ($data !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    }

    $response = curl_exec($ch);
    if ($response === false) {
        Response::error('Unable to reach data store', 500);
    }

    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $decoded = json_decode($response, true);
    if ($decoded === null && $response !== '' && $response !== 'null') {
        Response::error('Invalid response from data store', 500);
    }

    if ($status >= 400) {
        Response::error('Data store error', $status, ['details' => $decoded]);
    }

    return $decoded ?? [];
}

function db_find_user_by_email(string $email): ?array
{
    $users = db_request('GET', 'users', null, ['email' => $email]);
    return $users[0] ?? null;
}

function db_create_user(array $data): array
{
    return db_request('POST', 'users', $data);
}

function db_find_user_by_id($id): ?array
{
    $users = db_request('GET', 'users', null, ['id' => $id]);
    return $users[0] ?? null;
}

function db_create_device(array $data): array
{
    return db_request('POST', 'devices', $data);
}

function db_get_devices_by_user(int $userId): array
{
    return db_request('GET', 'devices', null, ['user_id' => $userId]);
}

function db_create_login(array $data): array
{
    return db_request('POST', 'logins', $data);
}

function db_find_login_by_login_id(string $loginId): ?array
{
    $logins = db_request('GET', 'logins', null, ['login_id' => $loginId]);
    return $logins[0] ?? null;
}

function db_update_login(int $id, array $data): array
{
    return db_request('PATCH', "logins/$id", $data);
}

function db_get_pending_logins_by_user(int $userId): array
{
    return db_request('GET', 'logins', null, ['user_id' => $userId, 'status' => 'PENDING', '_sort' => 'created_at', '_order' => 'desc']);
}

function db_get_logins(array $params): array
{
    return db_request('GET', 'logins', null, $params);
}
