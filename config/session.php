<?php

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

function generateSessionToken() {
    return bin2hex(random_bytes(32));
}

function setSessionTokenCookie($token) {

    $expire = time() + (7 * 24 * 60 * 60); // neka istece kukito za 7 dena
    $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
    setcookie('session_token', $token, $expire, '/', '', $secure, true);
}

function clearSessionTokenCookie() {
    if (isset($_COOKIE['session_token'])) {
        setcookie('session_token', '', time() - 3600, '/');
    }
}
//proveruva dali e najavne korisnikot
function isLoggedIn() {
    $hasSession = isset($_SESSION['user_id']) && isset($_SESSION['username']);
    $hasToken = isset($_COOKIE['session_token']) && isset($_SESSION['session_token']);
    
    // cookie toKen dali e ist so session toKen
    if ($hasSession && $hasToken) {
        return $_COOKIE['session_token'] === $_SESSION['session_token'];
    }
    return false;
}

function requireLogin() {
    if (!isLoggedIn()) {
        header('Location: login.php');
        exit();
    }
}
function requireGuest() {
    if (isLoggedIn()) {
        header('Location: index.php');
        exit();
    }
}
//za logout gi brisheme session token cookie, sesijata i session cookie
function logout() {
    clearSessionTokenCookie();

    $_SESSION = array();

    if (isset($_COOKIE[session_name()])) {
        setcookie(session_name(), '', time() - 3600, '/');
    }
    session_destroy();
}

