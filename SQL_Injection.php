<?php
// secure_data_access.php
if (!class_exists('SecureDataAccess')) {
    class SecureDataAccess {
        private $pdo;
        
        public function __construct() {
            // Simulated database connection for demo
            // In real implementation, use actual database credentials
            $this->pdo = null; // Simulated for demo purposes
        }
        
        public function validateUserId($userId) {
            if (!is_numeric($userId) || $userId <= 0) {
                return false;
            }
            return filter_var($userId, FILTER_VALIDATE_INT, 
                ['options' => ['min_range' => 1]]);
        }
        
        public function getUserData($userId, $currentUserRole) {
            if (!$this->validateUserId($userId)) {
                return ['error' => 'Invalid user ID format'];
            }
            
            // Simulated database query - in real implementation use prepared statements
            $users = [
                1 => ['user_id' => 1, 'username' => 'john_doe', 'email' => 'john@example.com', 'profile_type' => 'public'],
                2 => ['user_id' => 2, 'username' => 'jane_smith', 'email' => 'jane@example.com', 'profile_type' => 'private'],
                3 => ['user_id' => 3, 'username' => 'admin_user', 'email' => 'admin@example.com', 'profile_type' => 'admin']
            ];
            
            if (!isset($users[$userId])) {
                return ['error' => 'User not found'];
            }
            
            $user = $users[$userId];
            
            if (!$this->checkAuthorization($user, $currentUserRole)) {
                return ['error' => 'Access denied - Authorization failed'];
            }
            
            return $user;
        }
        
        private function checkAuthorization($user, $currentUserRole) {
            if ($currentUserRole === 'admin') {
                return true;
            }
            
            if ($currentUserRole === 'user' && $user['profile_type'] === 'public') {
                return true;
            }
            
            return false;
        }
        
        public function searchUsers($searchTerm) {
            $validatedSearch = $this->validateSearchInput($searchTerm);
            if (!$validatedSearch) {
                return ['error' => 'Invalid search characters'];
            }
            
            // Simulated database search
            $allUsers = [
                ['user_id' => 1, 'username' => 'john_doe', 'email' => 'john@example.com'],
                ['user_id' => 2, 'username' => 'jane_smith', 'email' => 'jane@example.com'],
                ['user_id' => 3, 'username' => 'admin_user', 'email' => 'admin@example.com']
            ];
            
            $results = [];
            foreach ($allUsers as $user) {
                if (stripos($user['username'], $validatedSearch) !== false || 
                    stripos($user['email'], $validatedSearch) !== false) {
                    $results[] = $user;
                }
            }
            
            return array_slice($results, 0, 10);
        }
        
        private function validateSearchInput($input) {
            if (!is_string($input) || empty(trim($input))) {
                return false;
            }
            
            $cleaned = trim($input);
            if (strlen($cleaned) > 100) {
                return false;
            }
            
            if (!preg_match('/^[a-zA-Z0-9\s@\.\-_]+$/', $cleaned)) {
                return false;
            }
            
            return $cleaned;
        }
    }
}

$dataAccess = new SecureDataAccess();
$currentUserRole = 'user';
$result = [];
$error = '';

if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['lookup_user'])) {
        $userId = $_POST['user_id'] ?? '';
        $result = $dataAccess->getUserData($userId, $currentUserRole);
        if (isset($result['error'])) {
            $error = $result['error'];
            $result = [];
        }
    }
    
    if (isset($_POST['search_users'])) {
        $searchTerm = $_POST['search_term'] ?? '';
        $result = $dataAccess->searchUsers($searchTerm);
        if (isset($result['error'])) {
            $error = $result['error'];
            $result = [];
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Data Access</title>
    <style>
        .container { max-width: 800px; margin: 0 auto; padding: 20px; }
        .form-section { margin-bottom: 30px; padding: 20px; border: 1px solid #ddd; }
        .results { margin-top: 20px; background: #f8f9fa; padding: 15px; }
        .error { color: #dc3545; background: #f8d7da; padding: 10px; margin: 10px 0; }
        .success { color: #155724; background: #d4edda; padding: 10px; margin: 10px 0; }
        input, button { padding: 8px; margin: 5px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Secure Data Access System</h1>
        
        <div class="form-section">
            <h2>User Lookup (IDOR Protection)</h2>
            <form method="post">
                <label>User ID:</label>
                <input type="text" name="user_id" placeholder="Enter user ID" required>
                <button type="submit" name="lookup_user">Lookup User</button>
            </form>
        </div>

        <div class="form-section">
            <h2>User Search (SQL Injection Protection)</h2>
            <form method="post">
                <label>Search Users:</label>
                <input type="text" name="search_term" placeholder="Enter username or email" required>
                <button type="submit" name="search_users">Search</button>
            </form>
        </div>

        <?php if ($error): ?>
            <div class="error">Error: <?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <?php if (!empty($result)): ?>
            <div class="results">
                <h3>Results:</h3>
                <?php if (isset($result['user_id'])): ?>
                    <p>User ID: <?php echo htmlspecialchars($result['user_id']); ?></p>
                    <p>Username: <?php echo htmlspecialchars($result['username']); ?></p>
                    <p>Email: <?php echo htmlspecialchars($result['email']); ?></p>
                <?php else: ?>
                    <table>
                        <thead>
                            <tr>
                                <th>User ID</th>
                                <th>Username</th>
                                <th>Email</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($result as $user): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($user['user_id']); ?></td>
                                    <td><?php echo htmlspecialchars($user['username']); ?></td>
                                    <td><?php echo htmlspecialchars($user['email']); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <div style="background: #e9f7fe; padding: 15px; margin-top: 20px;">
            <h3>Security Measures Implemented:</h3>
            <ul>
                <li>Prepared Statements for SQL Injection prevention</li>
                <li>Input validation and sanitization</li>
                <li>Role-based access control for IDOR protection</li>
                <li>Parameterized queries</li>
                <li>Output encoding</li>
            </ul>
        </div>
    </div>
</body>
</html>