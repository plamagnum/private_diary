<?php
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'httponly' => true,
    'samesite' => 'Strict',
    'secure'   => !empty($_SERVER['HTTPS']),
]);
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

function readJson(): array {
    $data = json_decode(file_get_contents('php://input'), true);
    return is_array($data) ? $data : [];
}

function jsonError(int $code, string $msg): never {
    http_response_code($code);
    echo json_encode(['error' => $msg]);
    exit;
}

const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_WINDOW_MIN   = 15;

function ensureAttemptsTable(PDO $pdo): void {
    $pdo->exec("CREATE TABLE IF NOT EXISTS login_attempts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        ip VARCHAR(45) NOT NULL,
        username VARCHAR(50) NOT NULL,
        attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX (ip, attempted_at),
        INDEX (username, attempted_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
}

function tooManyAttempts(PDO $pdo, string $ip, string $username): bool {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM login_attempts
        WHERE (ip = ? OR username = ?) AND attempted_at > (NOW() - INTERVAL " . LOGIN_WINDOW_MIN . " MINUTE)");
    $stmt->execute([$ip, $username]);
    return (int)$stmt->fetchColumn() >= MAX_LOGIN_ATTEMPTS;
}

$method = $_SERVER['REQUEST_METHOD'];
$path   = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// --- Реєстрація ---
if ($method === 'POST' && $path === '/api/auth/register') {
    $data = readJson();
    $username = trim((string)($data['username'] ?? ''));
    $password = (string)($data['password'] ?? '');

    if (mb_strlen($username) < 3 || mb_strlen($username) > 50 || strlen($password) < 6 || strlen($password) > 72) {
        http_response_code(400);
        echo json_encode(['error' => 'Логін 3–50, пароль 6–72 символи']);
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
    $data = readJson();
    $username = mb_substr(trim((string)($data['username'] ?? '')), 0, 50);
    $password = (string)($data['password'] ?? '');

    $pdo = getDB();
    ensureAttemptsTable($pdo);
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    if (tooManyAttempts($pdo, $ip, $username)) {
        header('Retry-After: ' . (LOGIN_WINDOW_MIN * 60));
        jsonError(429, 'Забагато спроб. Спробуйте пізніше');
    }
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password_hash'])) {
        $pdo->prepare("DELETE FROM login_attempts WHERE ip = ? OR username = ?")->execute([$ip, $username]);
        session_regenerate_id(true);
        $_SESSION = ['user_id' => (int)$user['id']];
        echo json_encode([
            'id'       => $user['id'],
            'username' => $user['username'],
            'role'     => $user['role'],
        ]);
    } else {
        $pdo->prepare("INSERT INTO login_attempts (ip, username) VALUES (?, ?)")->execute([$ip, $username]);
        http_response_code(401);
        echo json_encode(['error' => 'Невірний логін або пароль']);
    }
    exit;
}

// --- Вихід ---
if ($method === 'POST' && $path === '/api/auth/logout') {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 3600, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
    }
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
    $data = readJson();
    $salt         = $data['salt']         ?? '';
    $verification = $data['verification'] ?? '';

    if (!is_string($salt) || !is_string($verification) || $salt === '' || $verification === '') {
        http_response_code(400);
        echo json_encode(['error' => 'Відсутні salt або verification']);
        exit;
    }

    $pdo = getDB();
    $stmt = $pdo->prepare("SELECT diary_verification FROM users WHERE id = ?");
    $stmt->execute([$user['id']]);
    if ($stmt->fetchColumn()) {
        jsonError(409, 'Ключ щоденника вже встановлено');
    }

    $stmt = $pdo->prepare("UPDATE users SET diary_salt = ?, diary_verification = ? WHERE id = ?");
    $stmt->execute([$salt, password_hash($verification, PASSWORD_BCRYPT), $user['id']]);
    echo json_encode(['success' => true]);
    exit;
}

// --- Перевірити ключ щоденника (розблокувати сесію) ---
if ($method === 'POST' && $path === '/api/diary/verify-key') {
    $user = requireAuth();
    $data = readJson();
    $attempt = $data['verification'] ?? '';
    if (!is_string($attempt)) $attempt = '';

    $pdo = getDB();
    $stmt = $pdo->prepare("SELECT diary_verification FROM users WHERE id = ?");
    $stmt->execute([$user['id']]);
    $row = $stmt->fetch();

    $stored = $row['diary_verification'] ?? '';
    $ok = false;
    if ($stored !== '' && $attempt !== '') {
        if (str_starts_with($stored, '$2y$')) {
            $ok = password_verify($attempt, $stored);
        } elseif (hash_equals($stored, $attempt)) {
            // застарілий формат (відкритий текст) — перехешовуємо
            $ok = true;
            $pdo->prepare("UPDATE users SET diary_verification = ? WHERE id = ?")
                ->execute([password_hash($attempt, PASSWORD_BCRYPT), $user['id']]);
        }
    }

    if ($ok) {
        $_SESSION['diary_unlocked'] = (int)$user['id'];
        echo json_encode(['success' => true]);
    } else {
        http_response_code(403);
        echo json_encode(['error' => 'Невірний ключ щоденника']);
    }
    exit;
}
