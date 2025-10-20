# DVWA Web Security Lab – Vulnerability Analysis and Mitigation

This repository documents my hands-on exploration of common **web application vulnerabilities** using the **Damn Vulnerable Web Application (DVWA)**.  
The goal was to **identify, exploit, and then implement secure mitigations** for various attack vectors that affect LAMP-based web applications.

---

## 🧩 Overview

The lab focused on understanding and securing applications against:
- SQL Injection (SQLi)
- Cross-Site Scripting (Reflected & Stored)
- Cross-Site Request Forgery (CSRF)
- Insecure Direct Object References (IDOR)
- Weak Session IDs / Session Fixation
- File Upload & Command Injection
- File Inclusion (LFI/RFI)

Each vulnerability was:
1. Identified and exploited on DVWA in a controlled environment  
2. Analyzed to determine its root cause  
3. Mitigated using secure coding techniques and best practices

---

### Part E - Implemented Fixes & Mitigations

#### 1. **Secure Session Management** (`Session_ID.php`)
- **Vulnerability:** Weak Session IDs / Session Fixation
- **Mitigation:** 
  - Strict session mode enforcement
  - HTTPOnly & Secure cookies
  - Session fingerprinting
  - Automatic timeout (30 minutes)
  - Periodic session regeneration
  - Cryptographic token validation

#### 2. **SQL Injection & IDOR Protection** (`SQL_Injection.php`)
- **Vulnerabilities:** SQL Injection, Insecure Direct Object References
- **Mitigation:**
  - Prepared statements with PDO
  - Input validation for user IDs
  - Role-based access control
  - CSRF token implementation
  - Output encoding

#### 3. **XSS Prevention System** (`XSS.php`)
- **Vulnerability:** Reflected Cross-Site Scripting
- **Mitigation:**
  - Input validation with allowlists
  - Context-aware output encoding
  - Content Security Policy headers
  - HTML special character encoding
  - Safe HTML filtering

### Part C - CSRF Demonstration (`CSRF_code.html`)
- **Advanced CSRF Attack Laboratory** with multiple attack vectors:
  - GET Request CSRF
  - POST Request CSRF  
  - Image Tag CSRF
  - Stealth Auto-Attack
- Includes real-time attack logging and educational content

## 📚 Lessons Learned

- Every input must be validated, sanitized, and encoded based on its context.  
- Parameterized queries completely eliminate SQL injection risks.  
- CSRF tokens ensure requests are intentional and user-initiated.  
- Session cookies must be protected with secure attributes.  
- Defense-in-depth (headers, CSP, validation, encoding) is key to modern web security.  

---

## ✅ Conclusion

This project demonstrates how common vulnerabilities can compromise insecure web applications, and how secure coding practices can prevent them.  
By integrating layered defenses, we can build **resilient, production-ready web applications** that uphold **confidentiality, integrity, and availability**.  

---

**Name:** Sahil Mehta  
**UID:** 2023300143  
**Experiment No:** 7  
**Institute:** Sardar Patel Institute of Technology

---