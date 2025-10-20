<?php
// secure_session_handler.php
class SessionProtector {
    private $sessionTimeout = 1800; // 30 minutes
    
    public function startSecureSession() {
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.cookie_httponly', '1');
        ini_set('session.cookie_samesite', 'Strict');
        
        if ($this->isHttps()) {
            ini_set('session.cookie_secure', '1');
        }
        
        session_set_cookie_params([
            'lifetime' => 0,
            'path' => '/',
            'domain' => '',
            'secure' => $this->isHttps(),
            'httponly' => true,
            'samesite' => 'Strict'
        ]);
        
        session_name('APP_SECURE_SESSION');
        session_start();
        $this->validateSession();
    }
    
    private function isHttps() {
        return isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    }
    
    private function validateSession() {
        $currentFingerprint = $this->generateFingerprint();
        
        if (!isset($_SESSION['fingerprint'])) {
            $_SESSION['fingerprint'] = $currentFingerprint;
            $_SESSION['start_time'] = time();
        }
        
        if ($_SESSION['fingerprint'] !== $currentFingerprint) {
            $this->terminateSession();
            die("Session security violation detected");
        }
        
        if (isset($_SESSION['last_activity']) && 
            (time() - $_SESSION['last_activity'] > $this->sessionTimeout)) {
            $this->terminateSession();
            die("Session expired");
        }
        
        $_SESSION['last_activity'] = time();
        
        if (!isset($_SESSION['created'])) {
            $_SESSION['created'] = time();
        } else if (time() - $_SESSION['created'] > 1800) {
            session_regenerate_id(true);
            $_SESSION['created'] = time();
        }
    }
    
    private function generateFingerprint() {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $ipSegment = substr($_SERVER['REMOTE_ADDR'] ?? '', 0, 15);
        return hash('sha256', $userAgent . $ipSegment);
    }
    
    public function terminateSession() {
        $_SESSION = array();
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }
        session_destroy();
    }
    
    public function setAuthData($userId, $userRole) {
        $_SESSION['user_id'] = $userId;
        $_SESSION['user_role'] = $userRole;
        $_SESSION['login_time'] = time();
        session_regenerate_id(true);
    }
}

$session = new SessionProtector();
$session->startSecureSession();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    if ($username === 'admin' && $password === 'securepass') {
        $session->setAuthData(1, 'administrator');
        $loginMessage = "Login successful - Secure session established";
    } else {
        $loginMessage = "Invalid credentials";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Session Management</title>
    <style>
        .container { max-width: 600px; margin: 50px auto; padding: 20px; border: 1px solid #ccc; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        .info { background: #e9f7fe; padding: 15px; margin: 20px 0; border-left: 4px solid #007bff; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Secure Session Management System</h1>
        
        <div class="info">
            <h3>Security Features Active:</h3>
            <ul>
                <li>Strict Session Mode</li>
                <li>HTTPOnly and Secure Cookies</li>
                <li>Session Fingerprinting</li>
                <li>Automatic Timeout (30 minutes)</li>
                <li>Periodic Session Regeneration</li>
            </ul>
        </div>

        <?php if (isset($loginMessage)): ?>
            <div style="background: #d4edda; padding: 10px; margin: 10px 0;">
                <?php echo htmlspecialchars($loginMessage); ?>
            </div>
        <?php endif; ?>

        <form method="post">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" value="admin" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" value="securepass" required>
            </div>
            <button type="submit" name="login">Establish Secure Session</button>
        </form>

        <div class="info">
            <h3>Session Information:</h3>
            <p>Session ID: <?php echo substr(session_id(), 0, 10) . '...'; ?></p>
            <p>Fingerprint: <?php echo substr($_SESSION['fingerprint'] ?? 'Not set', 0, 16) . '...'; ?></p>
            <p>Last Activity: <?php echo date('H:i:s', $_SESSION['last_activity'] ?? time()); ?></p>
        </div>
    </div>
</body>
</html>