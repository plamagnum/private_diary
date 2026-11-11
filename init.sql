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

-- Адміністратор за замовчуванням.
-- Пароль 'admin123' встановлюється скриптом setup.sh після старту БД
-- (реальний bcrypt-хеш генерується через PHP).
INSERT INTO users (username, password_hash, role)
VALUES ('admin', 'placeholder', 'admin')
ON DUPLICATE KEY UPDATE username=username;
