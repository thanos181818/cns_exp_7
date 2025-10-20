<?php
// xss_protection_system.php
class XSSProtector {
    private $contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'";
    
    public function __construct() {
        header("X-Content-Type-Options: nosniff");
        header("X-XSS-Protection: 1; mode=block");
        header("Content-Security-Policy: " . $this->contentSecurityPolicy);
    }
    
    public function sanitizeInput($input, $type = 'text') {
        if (!is_string($input)) {
            return '';
        }
        
        $cleaned = trim($input);
        
        switch ($type) {
            case 'email':
                return $this->validateEmail($cleaned);
            case 'name':
                return $this->validateName($cleaned);
            case 'message':
                return $this->validateMessage($cleaned);
            case 'html':
                return $this->sanitizeHTML($cleaned);
            default:
                return $this->validateText($cleaned);
        }
    }
    
    private function validateEmail($email) {
        if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return filter_var($email, FILTER_SANITIZE_EMAIL);
        }
        return '';
    }
    
    private function validateName($name) {
        if (preg_match('/^[a-zA-Z\s\-]{1,50}$/', $name)) {
            return htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
        }
        return '';
    }
    
    private function validateMessage($message) {
        if (strlen($message) > 1000) {
            return '';
        }
        
        $allowed = '/[^a-zA-Z0-9\s\.\,\!\?\-\_\(\)\@\#\$\&\+\=\:;]/';
        if (preg_match($allowed, $message)) {
            return '';
        }
        
        return htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
    }
    
    private function validateText($text) {
        if (strlen($text) > 500) {
            return '';
        }
        
        $cleaned = strip_tags($text);
        return htmlspecialchars($cleaned, ENT_QUOTES, 'UTF-8');
    }
    
    private function sanitizeHTML($html) {
        $allowedTags = '<p><br><strong><em><ul><ol><li><a>';
        $cleaned = strip_tags($html, $allowedTags);
        
        $cleaned = preg_replace('/javascript:/i', '', $cleaned);
        $cleaned = preg_replace('/onclick|onload|onerror/i', '', $cleaned);
        
        return $cleaned;
    }
    
    public function outputSafe($data, $context = 'html') {
        if (is_array($data)) {
            return array_map([$this, 'outputSafe'], $data);
        }
        
        switch ($context) {
            case 'html':
                return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
            case 'attribute':
                return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
            case 'url':
                return urlencode($data);
            default:
                return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
        }
    }
}

$xssProtector = new XSSProtector();
$formData = [];
$submissionMessage = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = $xssProtector->sanitizeInput($_POST['name'] ?? '', 'name');
    $email = $xssProtector->sanitizeInput($_POST['email'] ?? '', 'email');
    $message = $xssProtector->sanitizeInput($_POST['message'] ?? '', 'message');
    $comment = $xssProtector->sanitizeInput($_POST['comment'] ?? '', 'html');
    
    if ($name && $email && $message) {
        $formData = [
            'name' => $name,
            'email' => $email,
            'message' => $message,
            'comment' => $comment,
            'timestamp' => date('Y-m-d H:i:s')
        ];
        $submissionMessage = "Form submitted successfully!";
    } else {
        $submissionMessage = "Please check your input and try again.";
    }
}

$searchQuery = '';
$searchResults = [];
if (isset($_GET['q'])) {
    $searchQuery = $xssProtector->sanitizeInput($_GET['q'], 'text');
    if ($searchQuery) {
        $searchResults = [
            "You searched for: " . $searchQuery,
            "Result 1 related to " . $searchQuery,
            "Result 2 matching " . $searchQuery
        ];
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Protection System</title>
    <style>
        .container { max-width: 800px; margin: 0 auto; padding: 20px; }
        .form-section { margin-bottom: 30px; padding: 20px; border: 1px solid #ddd; }
        .results { background: #f8f9fa; padding: 15px; margin: 10px 0; }
        .message { padding: 10px; margin: 10px 0; }
        .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        input, textarea, button { width: 100%; padding: 8px; margin: 5px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Cross-Site Scripting (XSS) Protection System</h1>
        
        <div class="form-section">
            <h2>Contact Form (Input Sanitization)</h2>
            <form method="post">
                <div>
                    <label>Name:</label>
                    <input type="text" name="name" placeholder="Enter your name" required>
                </div>
                <div>
                    <label>Email:</label>
                    <input type="email" name="email" placeholder="Enter your email" required>
                </div>
                <div>
                    <label>Message:</label>
                    <textarea name="message" placeholder="Enter your message" rows="4" required></textarea>
                </div>
                <div>
                    <label>Comment (HTML allowed):</label>
                    <textarea name="comment" placeholder="Limited HTML allowed" rows="3"></textarea>
                </div>
                <button type="submit">Submit Securely</button>
            </form>
        </div>

        <div class="form-section">
            <h2>Search Function (Output Encoding)</h2>
            <form method="get">
                <input type="text" name="q" placeholder="Search..." value="<?php echo $xssProtector->outputSafe($searchQuery, 'attribute'); ?>">
                <button type="submit">Search</button>
            </form>
            
            <?php if (!empty($searchResults)): ?>
                <div class="results">
                    <h3>Search Results:</h3>
                    <?php foreach ($searchResults as $result): ?>
                        <p><?php echo $xssProtector->outputSafe($result); ?></p>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>

        <?php if ($submissionMessage): ?>
            <div class="message <?php echo strpos($submissionMessage, 'successfully') !== false ? 'success' : 'error'; ?>">
                <?php echo $xssProtector->outputSafe($submissionMessage); ?>
            </div>
        <?php endif; ?>

        <?php if (!empty($formData)): ?>
            <div class="results">
                <h3>Submitted Data (Safely Displayed):</h3>
                <p><strong>Name:</strong> <?php echo $xssProtector->outputSafe($formData['name']); ?></p>
                <p><strong>Email:</strong> <?php echo $xssProtector->outputSafe($formData['email']); ?></p>
                <p><strong>Message:</strong> <?php echo $xssProtector->outputSafe($formData['message']); ?></p>
                <p><strong>Comment:</strong> <?php echo $formData['comment']; ?></p>
                <p><strong>Timestamp:</strong> <?php echo $xssProtector->outputSafe($formData['timestamp']); ?></p>
            </div>
        <?php endif; ?>

        <div style="background: #e9f7fe; padding: 15px; margin-top: 20px;">
            <h3>XSS Protection Measures:</h3>
            <ul>
                <li>Input validation and sanitization</li>
                <li>Context-aware output encoding</li>
                <li>Content Security Policy headers</li>
                <li>HTML special characters encoding</li>
                <li>Strict character allowlists</li>
                <li>Safe HTML filtering</li>
            </ul>
        </div>
    </div>
</body>
</html>