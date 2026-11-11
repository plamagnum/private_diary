<?php
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

require_once 'db.php';
require_once 'auth.php';   // обробляє /api/auth/*, /api/diary/set-key, /api/diary/verify-key

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

if (str_starts_with($path, '/api/diary')) {
    require_once 'diary.php';
} elseif (str_starts_with($path, '/api/admin')) {
    require_once 'admin.php';
} else {
    http_response_code(404);
    echo json_encode(['error' => 'Маршрут не знайдено']);
}
