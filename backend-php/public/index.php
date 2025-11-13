<?php

require_once __DIR__ . '/../src/bootstrap.php';

use App\Lib\Response;
use function App\Routes\handle_device_approve;
use function App\Routes\handle_device_link_complete;
use function App\Routes\handle_device_link_start;
use function App\Routes\handle_device_reject;
use function App\Routes\handle_device_sessions_end;
use function App\Routes\handle_device_pending;
use function App\Routes\handle_login_request;
use function App\Routes\handle_login_status;
use function App\Routes\handle_me;
use function App\Routes\handle_register;

$origin = $_SERVER['HTTP_ORIGIN'] ?? null;
$allowedOrigin = env('CORS_ORIGIN', '*');
if ($allowedOrigin === '*') {
    header('Access-Control-Allow-Origin: *');
} elseif ($origin && $origin === $allowedOrigin) {
    header('Access-Control-Allow-Origin: ' . $origin);
}
header('Access-Control-Allow-Methods: GET,POST,OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Access-Control-Allow-Credentials: true');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'];

switch (true) {
    case $path === '/api/register' && $method === 'POST':
        handle_register(getJsonInput());
        break;
    case $path === '/api/login/request' && $method === 'POST':
        handle_login_request(getJsonInput());
        break;
    case $path === '/api/login/status' && $method === 'GET':
        $loginId = $_GET['login_id'] ?? '';
        if (!$loginId) {
            Response::error('Missing login_id', 422);
        }
        handle_login_status($loginId);
        break;
    case $path === '/api/me' && $method === 'GET':
        handle_me($_SERVER['HTTP_AUTHORIZATION'] ?? null);
        break;
    case $path === '/api/device/link/start' && $method === 'POST':
        handle_device_link_start(getJsonInput());
        break;
    case $path === '/api/device/link/complete' && $method === 'POST':
        handle_device_link_complete(getJsonInput());
        break;
    case $path === '/api/device/reject' && $method === 'POST':
        handle_device_reject(getJsonInput());
        break;
    case $path === '/api/device/sessions/end' && $method === 'POST':
        handle_device_sessions_end(getJsonInput());
        break;
    case $path === '/api/device/pending' && $method === 'GET':
        $email = $_GET['email'] ?? '';
        if (!$email) {
            Response::error('Missing email', 422);
        }
        handle_device_pending($email);
        break;
    case $path === '/api/device/approve' && $method === 'POST':
        handle_device_approve(getJsonInput());
        break;
    default:
        Response::error('Not Found', 404);
}
