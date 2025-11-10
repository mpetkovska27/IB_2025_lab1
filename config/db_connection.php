<?php
function connectDatabase(): SQLite3 {
    $dbDir = __DIR__ . '/../database';
    if (!is_dir($dbDir)) {
        mkdir($dbDir, 0755, true);
    }
    $db = new SQLite3($dbDir . '/db.sqlite');
    initializeDatabase($db);
    return $db;
}

function initializeDatabase($db) {
    $createTableQuery = <<<SQL
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    first_name TEXT,
    last_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
SQL;

    if (!$db->exec($createTableQuery)) {
        echo "Error creating table: " . $db->lastErrorMsg();
    }
}
