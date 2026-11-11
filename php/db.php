<?php
// Підключення до БД через PDO (singleton)
function getDB(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $host = getenv('DB_HOST') ?: 'db';
        $db   = getenv('DB_NAME') ?: 'diary';
        $user = getenv('DB_USER');
        $pass = getenv('DB_PASS');
        if ($user === false || $pass === false) {
            throw new RuntimeException('DB_USER/DB_PASS не задані');
        }
        $dsn = "mysql:host=$host;dbname=$db;charset=utf8mb4";
        $pdo = new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        bootstrapAdmin($pdo);
    }
    return $pdo;
}

// Встановлює пароль адміністратора з ADMIN_PASSWORD, поки в БД лежить заглушка з init.sql
function bootstrapAdmin(PDO $pdo): void {
    $adminPass = getenv('ADMIN_PASSWORD');
    if (!$adminPass) return;
    $stmt = $pdo->prepare("UPDATE users SET password_hash = ? WHERE username = 'admin' AND password_hash = 'placeholder'");
    $stmt->execute([password_hash($adminPass, PASSWORD_BCRYPT)]);
}
