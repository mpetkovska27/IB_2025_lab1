<?php
require_once 'config/session.php';
require_once 'includes/auth.php';

requireLogin();

$user = getCurrentUser();
$allUsers = getAllUsers();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Authentication System - Lab Exercise</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body class="index-page">
    <!-- Navbar -->
    <nav class="navbar">
        <div class="nav-container">
            <div class="nav-brand">
                <h2>Auth System</h2>
            </div>
            <div class="nav-menu">
                <span class="user-greeting">Welcome, <?php echo htmlspecialchars($user['username']); ?>!</span>
                <a href="edit_profile.php" class="btn btn-nav-secondary">Edit Profile</a>
                <a href="logout.php" class="btn btn-nav">Logout</a>
            </div>
        </div>
    </nav>

    <!-- Hero Section -->
    <section class="hero">
        <div class="hero-content">
            <h1>User Authentication System</h1>
            <p class="hero-subtitle">Lab exercise, made by Martina Petkovska - 223313,  that implements a complete authentication solution for secure user management</p>
        </div>
    </section>

    <!-- Main Content -->
    <main class="main-content">
        <div class="content-wrapper">
            <!-- About Section -->
            <section class="content-section">
                <h2>About This Lab Exercise</h2>
                <p>This application demonstrates a complete user authentication system implemented as part of a laboratory exercise. The system provides:
                    <br/>- secure user registration,
                    <br/>- login functionality
                    <br/>- and user data management.</p>

            </section>

            <!-- User Account Section -->
            <?php if ($user): ?>
            <section class="content-section">
                <h2>Your Account Information</h2>
                <div class="account-info">
                    <div class="info-item">
                        <span class="info-label">Username:</span>
                        <span class="info-value"><?php echo htmlspecialchars($user['username']); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Email:</span>
                        <span class="info-value"><?php echo htmlspecialchars($user['email']); ?></span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Registered on:</span>
                        <span class="info-value"><?php echo date('F j, Y \a\t g:i A', strtotime($user['created_at'])); ?></span>
                    </div>
                </div>
            </section>
            <?php endif; ?>

            <!-- Users List Section -->
            <section class="content-section">
                <h2>Registered Users</h2>
                <?php if (empty($allUsers)): ?>
                    <p class="no-users">No users registered yet.</p>
                <?php else: ?>
                    <div class="users-table-container">
                        <table class="users-table">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Username</th>
                                    <th>Email</th>
                                    <th>Registered</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($allUsers as $u): ?>
                                    <tr <?php echo ($user && $u['id'] == $user['id']) ? 'class="current-user"' : ''; ?>>
                                        <td><?php echo htmlspecialchars($u['id']); ?></td>
                                        <td><?php echo htmlspecialchars($u['username']); ?></td>
                                        <td><?php echo htmlspecialchars($u['email']); ?></td>
                                        <td><?php echo date('M j, Y', strtotime($u['created_at'])); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    <p class="users-count">Total users: <?php echo count($allUsers); ?></p>
                <?php endif; ?>
            </section>
        </div>
    </main>

    <!-- Footer -->
    <footer class="footer">
        <div class="footer-content">
            <p>&copy; 2025 User Authentication System - Laboratory Exercise 1</p>
        </div>
    </footer>
</body>
</html>
