<?php
session_start();
require_once 'db.php';

/**
 * Повертає поточного авторизованого користувача або null
 */
function getCurrentUser(): ?array {
    if (!isset($_SESSION['user_id'])) return null;
    $pdo = getDB();
    $stmt = $pdo->prepare("SELECT id, username, role FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    return $stmt->fetch() ?: null;
}

/**
 * Middleware: вимагає авторизації
 */
function requireAuth(): array {
    $user = getCurrentUser();
    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Необхідно увійти']);
        exit;
    }
    return $user;
}

/**
 * Middleware: вимагає роль адміністратора
 */
function requireAdmin(): array {
    $user = requireAuth();
    if ($user['role'] !== 'admin') {
        http_response_code(403);
        echo json_encode(['error' => 'Доступ заборонено']);
        exit;
    }
    return $user;
}

$method = $_SERVER['REQUEST_METHOD'];
$path   = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// --- Реєстрація ---
if ($method === 'POST' && $path === '/api/auth/register') {
    $data = json_decode(file_get_contents('php://input'), true);
    $username = trim($data['username'] ?? '');
    $password = $data['password'] ?? '';

    if (strlen($username) < 3 || strlen($password) < 6) {
        http_response_code(400);
        echo json_encode(['error' => 'Логін ≥3, пароль ≥6 символів']);
        exit;
    }

    $pdo = getDB();
    $hash = password_hash($password, PASSWORD_BCRYPT);
    try {
        $stmt = $pdo->prepare("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')");
        $stmt->execute([$username, $hash]);
        echo json_encode(['success' => true]);
    } catch (PDOException $e) {
        if ($e->getCode() == 23000) {
            http_response_code(409);
            echo json_encode(['error' => 'Користувач вже існує']);
        } else {
            http_response_code(500);
            echo json_encode(['error' => 'Помилка сервера']);
        }
    }
    exit;
}

// --- Вхід ---
if ($method === 'POST' && $path === '/api/auth/login') {
    $data = json_decode(file_get_contents('php://input'), true);
    $username = trim($data['username'] ?? '');
    $password = $data['password'] ?? '';

    $pdo = getDB();
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password_hash'])) {
        $_SESSION['user_id'] = $user['id'];
        echo json_encode([
            'id'       => $user['id'],
            'username' => $user['username'],
            'role'     => $user['role'],
        ]);
    } else {
        http_response_code(401);
        echo json_encode(['error' => 'Невірний логін або пароль']);
    }
    exit;
}

// --- Вихід ---
if ($method === 'POST' && $path === '/api/auth/logout') {
    session_destroy();
    echo json_encode(['success' => true]);
    exit;
}

// --- Поточний користувач (з diary_salt для клієнта) ---
if ($method === 'GET' && $path === '/api/auth/me') {
    $user = getCurrentUser();
    if ($user) {
        $pdo = getDB();
        $stmt = $pdo->prepare("SELECT diary_salt FROM users WHERE id = ?");
        $stmt->execute([$user['id']]);
        $row = $stmt->fetch();
        $user['diary_salt'] = $row['diary_salt'] ?? null;
        echo json_encode($user);
    } else {
        http_response_code(401);
        echo json_encode(['error' => 'Не авторизовано']);
    }
    exit;
}

// --- Зберегти параметри ключа щоденника (salt + verification) ---
if ($method === 'POST' && $path === '/api/diary/set-key') {
    $user = requireAuth();
    $data = json_decode(file_get_contents('php://input'), true);
    $salt         = $data['salt']         ?? '';
    $verification = $data['verification'] ?? '';

    if (empty($salt) || empty($verification)) {
        http_response_code(400);
        echo json_encode(['error' => 'Відсутні salt або verification']);
        exit;
    }

    $pdo = getDB();
    $stmt = $pdo->prepare("UPDATE users SET diary_salt = ?, diary_verification = ? WHERE id = ?");
    $stmt->execute([$salt, $verification, $user['id']]);
    echo json_encode(['success' => true]);
    exit;
}

// --- Перевірити ключ щоденника (розблокувати сесію) ---
if ($method === 'POST' && $path === '/api/diary/verify-key') {
    $user = requireAuth();
    $data = json_decode(file_get_contents('php://input'), true);
    $attempt = $data['verification'] ?? '';

    $pdo = getDB();
    $stmt = $pdo->prepare("SELECT diary_verification FROM users WHERE id = ?");
    $stmt->execute([$user['id']]);
    $row = $stmt->fetch();

    if ($row && $row['diary_verification'] && hash_equals($row['diary_verification'], $attempt)) {
        $_SESSION['diary_unlocked'] = true;
        echo json_encode(['success' => true]);
    } else {
        http_response_code(403);
        echo json_encode(['error' => 'Невірний ключ щоденника']);
    }
    exit;
}
