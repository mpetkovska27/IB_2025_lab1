<?php
require_once 'config/session.php';
require_once 'includes/auth.php';

requireLogin();

$user = getCurrentUser();
$error = '';
$success = '';

if (!$user) {
    header('Location: index.php');
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    if ($action === 'update_info') {
        $username = trim($_POST['username'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $firstName = trim($_POST['first_name'] ?? '');
        $lastName = trim($_POST['last_name'] ?? '');
        
        $result = updateUserInfo($user['id'], $username, $email, $firstName, $lastName);
        if ($result['success']) {
            $success = $result['message'];

            $user = getCurrentUser();
        } else {
            $error = $result['message'];
        }
    } elseif ($action === 'update_password') {
        $currentPassword = $_POST['current_password'] ?? '';
        $newPassword = $_POST['new_password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';
        
        $result = updatePassword($user['id'], $currentPassword, $newPassword, $confirmPassword);
        if ($result['success']) {
            $success = $result['message'];
        } else {
            $error = $result['message'];
        }
    } elseif ($action === 'delete_account') {
        $password = $_POST['delete_password'] ?? '';
        
        $result = deleteUser($user['id'], $password);
        if ($result['success']) {

            logout();
            header('Location: login.php');
            exit();
        } else {
            $error = $result['message'];
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Profile - User Authentication</title>
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
                <a href="index.php" class="btn btn-nav-secondary">Home</a>
                <a href="logout.php" class="btn btn-nav">Logout</a>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <main class="main-content">
        <div class="content-wrapper">
            <section class="content-section">
                <h2>Edit Profile</h2>
                
                <?php if ($error): ?>
                    <div class="alert alert-error"><?php echo htmlspecialchars($error); ?></div>
                <?php endif; ?>
                
                <?php if ($success): ?>
                    <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
                <?php endif; ?>
                
                <!-- Personal Information -->
                <div class="profile-section">
                    <h3>Personal Information</h3>
                    <form method="POST" action="edit_profile.php" class="profile-form">
                        <input type="hidden" name="action" value="update_info">
                        <input type="hidden" name="username" value="<?php echo htmlspecialchars($user['username']); ?>">
                        <input type="hidden" name="email" value="<?php echo htmlspecialchars($user['email']); ?>">
                        
                        <div class="form-group">
                            <label for="first_name">First Name:</label>
                            <input type="text" id="first_name" name="first_name" 
                                   value="<?php echo htmlspecialchars($user['first_name'] ?? ''); ?>"
                                   placeholder="Enter your first name">
                        </div>
                        
                        <div class="form-group">
                            <label for="last_name">Last Name:</label>
                            <input type="text" id="last_name" name="last_name" 
                                   value="<?php echo htmlspecialchars($user['last_name'] ?? ''); ?>"
                                   placeholder="Enter your last name">
                        </div>
                        <div class="form-group">
                            <label for="username">Username:</label>
                            <input type="text" id="username" name="username" required
                                   value="<?php echo htmlspecialchars($user['username']); ?>"
                                   minlength="3" maxlength="50">
                        </div>

                        <div class="form-group">
                            <label for="email">Email Address:</label>
                            <input type="email" id="email" name="email" required
                                   value="<?php echo htmlspecialchars($user['email']); ?>">
                        </div>
                        <button type="submit" class="btn btn-primary">Update Personal Information</button>
                    </form>
                </div>
                
                <!-- Change Password -->
                <div class="profile-section">
                    <h3>Change Password</h3>
                    <form method="POST" action="edit_profile.php" class="profile-form">
                        <input type="hidden" name="action" value="update_password">
                        
                        <div class="form-group">
                            <label for="current_password">Current Password:</label>
                            <input type="password" id="current_password" name="current_password" required>
                        </div>
                        
                        <div class="form-group">
                            <label for="new_password">New Password:</label>
                            <input type="password" id="new_password" name="new_password" required 
                                   minlength="9">
                            <small class="password-hint">Password must be longer than 8 characters and contain at least one uppercase letter, one lowercase letter, one number, and one special character.</small>
                        </div>
                        
                        <div class="form-group">
                            <label for="confirm_password">Confirm New Password:</label>
                            <input type="password" id="confirm_password" name="confirm_password" required 
                                   minlength="9">
                        </div>
                        
                        <button type="submit" class="btn btn-primary">Change Password</button>
                    </form>
                </div>
                
                <!-- Delete Account -->
                <div class="profile-section danger-section">
                    <h3>Delete Account</h3>
                    <p class="danger-warning">
                        <strong>Warning:</strong> This action cannot be undone. All your data will be permanently deleted.
                    </p>
                    <form method="POST" action="edit_profile.php" class="profile-form" id="deleteForm" onsubmit="return confirmDelete()">
                        <input type="hidden" name="action" value="delete_account">
                        
                        <div class="form-group">
                            <label for="delete_password">Enter your password to confirm deletion:</label>
                            <input type="password" id="delete_password" name="delete_password" required 
                                   placeholder="Enter your password">
                        </div>
                        
                        <button type="submit" class="btn btn-danger">Delete My Account</button>
                    </form>
                </div>
                
                <div class="profile-actions">
                    <a href="index.php" class="btn btn-secondary">Back to Home</a>
                </div>
            </section>
        </div>
    </main>
    
    <script>
        function confirmDelete() {
            return confirm('Are you sure you want to delete your account? This action cannot be undone and all your data will be permanently deleted.');
        }
    </script>

    <!-- Footer -->
    <footer class="footer">
        <div class="footer-content">
            <p>&copy; 2025 User Authentication System - Laboratory Exercise 1</p>
        </div>
    </footer>
</body>
</html>

