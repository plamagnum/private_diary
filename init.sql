CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('user','admin') DEFAULT 'user',
    diary_salt VARCHAR(255) DEFAULT NULL,
    diary_verification TEXT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS entries (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    iv VARCHAR(64) NOT NULL,
    ciphertext LONGTEXT NOT NULL,
    tag VARCHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(45) NOT NULL,
    username VARCHAR(50) NOT NULL,
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX (ip, attempted_at),
    INDEX (username, attempted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Адміністратор: заглушка замінюється bcrypt-хешем пароля з ADMIN_PASSWORD
-- при першому підключенні PHP до БД (див. php/db.php).
INSERT INTO users (username, password_hash, role)
VALUES ('admin', 'placeholder', 'admin')
ON DUPLICATE KEY UPDATE username=username;
