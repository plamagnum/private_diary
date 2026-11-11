<?php
// Цей файл підключається з index.php лише для шляхів /api/diary/*
// Використовує $method, $path, $user з auth.php

function requireDiaryUnlocked() {
    if (empty($_SESSION['diary_unlocked'])) {
        http_response_code(403);
        echo json_encode(['error' => 'Спочатку введіть ключ щоденника']);
        exit;
    }
}

$user = requireAuth();

// --- Список записів поточного користувача ---
if ($method === 'GET' && $path === '/api/diary/entries') {
    requireDiaryUnlocked();
    $pdo = getDB();
    $stmt = $pdo->prepare("
        SELECT id, iv, ciphertext, tag, created_at, updated_at
        FROM entries WHERE user_id = ? ORDER BY updated_at DESC
    ");
    $stmt->execute([$user['id']]);
    echo json_encode($stmt->fetchAll());
    exit;
}

// --- Створити запис ---
if ($method === 'POST' && $path === '/api/diary/entries') {
    requireDiaryUnlocked();
    $data = json_decode(file_get_contents('php://input'), true);
    $iv         = $data['iv']         ?? '';
    $ciphertext = $data['ciphertext'] ?? '';
    $tag        = $data['tag']        ?? '';

    if (empty($iv) || empty($ciphertext)) {
        http_response_code(400);
        echo json_encode(['error' => 'Необхідні iv і ciphertext']);
        exit;
    }

    $pdo = getDB();
    $stmt = $pdo->prepare("INSERT INTO entries (user_id, iv, ciphertext, tag) VALUES (?, ?, ?, ?)");
    $stmt->execute([$user['id'], $iv, $ciphertext, $tag]);
    echo json_encode(['id' => $pdo->lastInsertId()]);
    exit;
}

// --- Оновити запис ---
if ($method === 'PUT' && preg_match('#^/api/diary/entries/(\d+)$#', $path, $m)) {
    requireDiaryUnlocked();
    $entryId = (int)$m[1];
    $data    = json_decode(file_get_contents('php://input'), true);

    $pdo = getDB();
    $stmt = $pdo->prepare("SELECT id FROM entries WHERE id = ? AND user_id = ?");
    $stmt->execute([$entryId, $user['id']]);
    if (!$stmt->fetch()) {
        http_response_code(404);
        echo json_encode(['error' => 'Запис не знайдено']);
        exit;
    }

    $stmt = $pdo->prepare("UPDATE entries SET iv = ?, ciphertext = ?, tag = ? WHERE id = ?");
    $stmt->execute([$data['iv'], $data['ciphertext'], $data['tag'] ?? '', $entryId]);
    echo json_encode(['success' => true]);
    exit;
}

// --- Видалити запис ---
if ($method === 'DELETE' && preg_match('#^/api/diary/entries/(\d+)$#', $path, $m)) {
    requireDiaryUnlocked();
    $entryId = (int)$m[1];
    $pdo = getDB();
    $stmt = $pdo->prepare("DELETE FROM entries WHERE id = ? AND user_id = ?");
    $stmt->execute([$entryId, $user['id']]);
    if ($stmt->rowCount() === 0) {
        http_response_code(404);
        echo json_encode(['error' => 'Запис не знайдено']);
    } else {
        echo json_encode(['success' => true]);
    }
    exit;
}
