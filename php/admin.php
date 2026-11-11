<?php
$user = requireAdmin();

// --- Список користувачів ---
if ($method === 'GET' && $path === '/api/admin/users') {
    $pdo = getDB();
    $stmt = $pdo->query("SELECT id, username, role, created_at FROM users");
    echo json_encode($stmt->fetchAll());
    exit;
}

// --- Видалити користувача ---
if ($method === 'DELETE' && preg_match('#^/api/admin/users/(\d+)$#', $path, $m)) {
    $userId = (int)$m[1];
    if ($userId == $user['id']) {
        http_response_code(400);
        echo json_encode(['error' => 'Не можна видалити самого себе']);
        exit;
    }
    $pdo = getDB();
    $stmt = $pdo->prepare("SELECT role FROM users WHERE id = ?");
    $stmt->execute([$userId]);
    $target = $stmt->fetchColumn();
    if ($target === false) {
        jsonError(404, 'Користувача не знайдено');
    }
    if ($target === 'admin') {
        jsonError(403, 'Не можна видалити адміністратора');
    }
    $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
    $stmt->execute([$userId]);
    echo json_encode(['success' => true]);
    exit;
}

// --- Усі записи (адміністратор бачить лише зашифровані блоби) ---
if ($method === 'GET' && $path === '/api/admin/entries') {
    $pdo = getDB();
    $stmt = $pdo->query("
        SELECT e.id, e.user_id, u.username, e.iv, e.ciphertext, e.tag,
               e.created_at, e.updated_at
        FROM entries e JOIN users u ON e.user_id = u.id
        ORDER BY e.updated_at DESC
    ");
    echo json_encode($stmt->fetchAll());
    exit;
}

// --- Видалити будь-який запис ---
if ($method === 'DELETE' && preg_match('#^/api/admin/entries/(\d+)$#', $path, $m)) {
    $pdo = getDB();
    $stmt = $pdo->prepare("DELETE FROM entries WHERE id = ?");
    $stmt->execute([(int)$m[1]]);
    echo json_encode(['success' => true]);
    exit;
}
