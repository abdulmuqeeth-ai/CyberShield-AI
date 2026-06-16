"""
CyberShield AI - Mini Security Toolkit
A lightweight cybersecurity analysis system
"""

import re
from datetime import datetime

class CyberShield:
    def __init__(self):
        self.suspicious_keywords = [
            'urgent', 'verify', 'account suspended', 'security alert',
            'update your information', 'click here', 'confirm your identity',
            'bank', 'password expired', 'unusual activity', 'verify your account'
        ]
        
        self.phishing_domains = [
            '.xyz', '.top', '.club', '.work', '.date', '.download',
            '.review', '.stream', '.trade', '.webcam', '.click'
        ]
        
        self.suspicious_patterns = [
            r'\d{5,}',
            r'[-_]{3,}',
            r'[A-Za-z0-9]{20,}',
        ]

    def analyze_email(self, email_text):
        """Detect if an email is phishing"""
        email_lower = email_text.lower()
        score = 0
        detected_keywords = []
        
        for keyword in self.suspicious_keywords:
            if keyword in email_lower:
                score += 1
                detected_keywords.append(keyword)
        
        urgency_words = ['immediately', 'now', 'asap', 'within 24 hours', 'urgent']
        for word in urgency_words:
            if word in email_lower:
                score += 0.5
        
        if 'http://' in email_lower or 'https://' in email_lower:
            score += 1
        
        if 'attachment' in email_lower or 'attached' in email_lower:
            if 'invoice' in email_lower or 'payment' in email_lower:
                score += 1
        
        if score >= 4:
            result = "🚨 PHISHING - High risk!"
            confidence = "High"
        elif score >= 2.5:
            result = "⚠️ SUSPICIOUS - Caution recommended"
            confidence = "Medium"
        else:
            result = "✅ SAFE - No immediate threats detected"
            confidence = "Low"
        
        return {
            'status': result,
            'confidence': confidence,
            'score': score,
            'detected_keywords': detected_keywords,
            'risk_level': 'High' if score >= 4 else 'Medium' if score >= 2.5 else 'Low'
        }

    def check_url(self, url):
        """Analyze URL for phishing indicators"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
        score = 0
        issues = []
        
        for tld in self.phishing_domains:
            if domain.endswith(tld):
                score += 1
                issues.append(f"Suspicious TLD: {tld}")
        
        if len(domain.replace('.', '')) > 30:
            score += 1
            issues.append("Very long domain name")
        
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, domain):
            score += 2
            issues.append("IP address used instead of domain")
        
        subdomain_count = domain.count('.') - 1
        if subdomain_count > 3:
            score += 1
            issues.append("Many subdomains (potential phishing)")
        
        for pattern in self.suspicious_patterns:
            if re.search(pattern, url):
                score += 1
                issues.append("Suspicious pattern in URL")
        
        phishing_words = ['login', 'verify', 'account', 'secure', 'update', 'confirm']
        for word in phishing_words:
            if word in domain or word in path:
                score += 0.5
        
        if score >= 3:
            result = "🚨 PHISHING URL - Do not open!"
        elif score >= 1.5:
            result = "⚠️ SUSPICIOUS - Verify before opening"
        else:
            result = "✅ SAFE URL - No obvious threats"
        
        return {
            'url': url,
            'status': result,
            'score': score,
            'issues': issues,
            'risk_level': 'High' if score >= 3 else 'Medium' if score >= 1.5 else 'Low'
        }

    def analyze_logs(self, log_file_path):
        """Analyze logs for security threats"""
        try:
            with open(log_file_path, 'r') as f:
                logs = f.readlines()
        except FileNotFoundError:
            return {"error": "Log file not found"}
        
        failed_attempts = []
        successful_logins = []
        ip_addresses = {}
        suspicious_ips = []
        
        for line in logs:
            if 'Failed' in line and ('login' in line or 'password' in line):
                ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
                if ip_match:
                    ip = ip_match.group()
                    ip_addresses[ip] = ip_addresses.get(ip, 0) + 1
                    failed_attempts.append(line.strip())
            
            if 'Success' in line and ('login' in line or 'authenticated' in line):
                successful_logins.append(line.strip())
        
        for ip, count in ip_addresses.items():
            if count >= 5:
                suspicious_ips.append({'ip': ip, 'attempts': count})
        
        report = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'total_logs_analyzed': len(logs),
            'failed_attempts': len(failed_attempts),
            'successful_logins': len(successful_logins),
            'unique_ips': len(ip_addresses),
            'brute_force_attempts': len(suspicious_ips),
            'suspicious_ips': suspicious_ips,
            'risk_level': 'High' if len(suspicious_ips) > 0 else 'Medium' if len(failed_attempts) > 10 else 'Low'
        }
        
        return report


# ============================================
# RUN THE PROGRAM
# ============================================
if __name__ == "__main__":
    shield = CyberShield()
    
    print("\n" + "="*60)
    print("🛡️  CYBERSHIELD AI - Security Analysis System")
    print("="*60 + "\n")
    
    # --- TEST 1: Phishing Email ---
    print("[1] 📧 EMAIL ANALYSIS")
    print("-" * 40)
    test_email = """
    URGENT: Your account has been compromised. 
    Click here to verify your identity immediately.
    Your bank account needs to be updated within 24 hours.
    """
    email_result = shield.analyze_email(test_email)
    print(f"Status: {email_result['status']}")
    print(f"Risk Level: {email_result['risk_level']}")
    print(f"Detected Keywords: {email_result['detected_keywords']}")
    print()
    
    # --- TEST 2: Suspicious URL ---
    print("[2] 🌐 URL ANALYSIS")
    print("-" * 40)
    test_url = "http://secure-login-verify-bank.xyz/login"
    url_result = shield.check_url(test_url)
    print(f"URL: {test_url}")
    print(f"Status: {url_result['status']}")
    print(f"Issues: {', '.join(url_result['issues'])}")
    print()
    
    # --- TEST 3: Log Analysis ---
    print("[3] 📊 LOG ANALYSIS")
    print("-" * 40)
    
    with open('sample_logs.txt', 'w') as f:
        f.write("192.168.1.1 - - [15/Jun/2024:10:15:23] Failed login attempt\n")
        f.write("192.168.1.1 - - [15/Jun/2024:10:15:25] Failed login attempt\n")
        f.write("192.168.1.1 - - [15/Jun/2024:10:15:27] Failed login attempt\n")
        f.write("192.168.1.1 - - [15/Jun/2024:10:15:29] Failed login attempt\n")
        f.write("192.168.1.1 - - [15/Jun/2024:10:15:31] Failed login attempt\n")
        f.write("10.0.0.5 - - [15/Jun/2024:11:20:10] Success login\n")
        f.write("10.0.0.5 - - [15/Jun/2024:11:25:15] Success login\n")
    
    log_result = shield.analyze_logs('sample_logs.txt')
    print(f"Logs Analyzed: {log_result['total_logs_analyzed']}")
    print(f"Failed Attempts: {log_result['failed_attempts']}")
    print(f"Brute Force Attempts: {log_result['brute_force_attempts']}")
    if log_result['suspicious_ips']:
        for ip in log_result['suspicious_ips']:
            print(f"⚠️ Suspicious IP: {ip['ip']} ({ip['attempts']} attempts)")
    
    print("\n" + "="*60)
    print("✅ Analysis Complete!")
    print("📅 " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("="*60)