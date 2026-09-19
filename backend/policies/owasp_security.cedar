// Paradox — OWASP Security Policies (Cedar)
// Evaluates security findings against OWASP Top 10 2021

// A01: Broken Access Control — Sensitive paths accessible
forbid(principal, action == Action::"pass", resource == Resource::"sensitive_path")
when { resource.accessible == true && resource.severity == "high" };

// A03: Injection — SQL injection detected
forbid(principal, action == Action::"pass", resource == Resource::"injection_test")
when { resource.injectable == true };

// A05: Security Misconfiguration — Missing headers
forbid(principal, action == Action::"pass", resource == Resource::"header_check")
when { resource.missing_count > 3 };

// A07: XSS — Cross-site scripting vulnerability
forbid(principal, action == Action::"pass", resource == Resource::"xss_test")
when { resource.reflected == true };

// A09: Logging & Monitoring — No security.txt
forbid(principal, action == Action::"pass", resource == Resource::"security_txt")
when { resource.exists == false };

// Rate limiting required for auth endpoints
forbid(principal, action == Action::"pass", resource == Resource::"rate_limit")
when { resource.rate_limited == false && resource.is_auth_endpoint == true };
