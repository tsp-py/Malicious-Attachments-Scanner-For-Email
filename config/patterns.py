suspicious_indicators = ["CreateObject", "WScript.Shell", "Execute", "JS", "JavaScript", "obj", "embed", "form", "XFA", 
                         "import os", "import sys", "exec(", "eval(", "subprocess","rm -rf", "sudo", "wget", "curl",
                         "Runtime.getRuntime().exec", "ProcessBuilder", "URLClassLoader", "password", "confidential", "secret"
                         ]
# Define patterns in the patterns dictionary
patterns = {
    'SQL Injection': r"(\+\s*input\s*\(\s*.\)|input\s\(\s*.\)\s\+\s*.|'.?\+.*?')",
    'Unsafe SQL Query': r"executeQuery\s*\(\s*['\"].?['\"]\s\+\s*request\.getParameter\(\s*.?\)\s\+\s*['\"].*?['\"]",
    'XSS Vulnerability': r"<script>.*</script>",
    'XXE Vulnerability': r"<!ENTITY\s.*SYSTEM",
    'File Stealing': r"with\s+open\([\"'].[\"'].\)\s+as\s+file",
    'Unvalidated Redirect': r"request\.getRequestDispatcher\s*\(\s*destination\s*\)",
    'Command Injection': r"(os\.system\s*\(\s*['\"].?['\"]\s\+\s*input\s*\(\s*.?\)\s\)|subprocess\.(call|Popen|run)\s*\(\s*['\"].?\+\s*input\s\(\s*.?\)\s['\"]\s*\))",
    'Hardcoded Secrets': r"(apikey\s*=\s*['\"].['\"]|token\s=\s*['\"].['\"]|password\s=\s*['\"].['\"]|secret\s=\s*['\"].*['\"])",
    'Directory Traversal': r"(open\s*\(\s*['\"].?\.\./.?['\"]\s*\)|os\.path\.join\s*\(\s*['\"].?\.\./.?['\"]\s*\))",
    'Insecure Deserialization': r"pickle\.loads\s*\(\s*input\s*\(\s*.?\)\s\)",
    'Path Injection': r"os\.path\.join\s*\(\s*input\s*\(\s*.?\)\s,\s*['\"].*['\"]\)",
    'LDAP Injection': r"(ldap\.search\s*\(\s*['\"].?\+\s*input\s\(\s*.?\)\s\))",
    'Buffer Overflow (C/C++)': r"(strcpy\s*\(\s*.?,\s*input\s\(\s*.?\)\s\)|strcat\s*\(\s*.?,\s*input\s\(\s*.?\)\s\))",
    'Cross-Site Request Forgery (CSRF) Token Missing': r"(form\s.?action\s=\s*['\"].['\"]\s(?!.*csrf_token))",
    'Weak Cryptography': r"(DES\.new|rc4|md5|sha1)",
    'SMB Exploit': r"(smbclient|psexec|exploit\s*ms17-010)",
    'File Encryption Routine': r"(AES\.new|RSA\.encrypt|cryptography\.fernet|cipher\.encrypt)",
    'PLC Command': r"(send_packet|write_register|plc_command)",
    'Zero-Day Exploit Reference': r"(exploit\s*zero-day|CVE-\d{4}-\d{4,5})",
    'MBR Overwrite': r"(write_mbr|dd\s*if=.*?mbr|bootrec)",
    'Filesystem Encryption': r"(encrypt_partition|chkdsk\s*/f)",
    'Macro Execution': r"(AutoOpen|Application.Run|Shell\(\s*['\"].?['\"]\s\))",
    'Payload Download': r"(wget\s+http|Invoke-WebRequest|curl\s+-O)",
    'Hardcoded IoT Credentials': r"(username\s*=\s*['\"].['\"]\s*password\s=\s*['\"].*['\"]|login_attempt)",
    'Brute Force Command': r"(telnet\s+ip|nc\s+-zv)",
    'Form Grabbing': r"(hookForm|intercept_input)",
    'Browser Injection': r"(document\.write\(\s*['\"].iframe|window\.location\s=\s*['\"].*['\"]\))",
    'Ransomware File Extension': r"\.encrypted|\.locked|\.payme",
    'Ransom Note Creation': r"(open\(['\"].README.['\"]|with\s+open\(['\"].*ransom_note['\"]\))",
    'Obfuscated Payload': r"(eval\(\s*base64|exec\(compile\()",
    'Backdoor Creation': r"(reverse_shell|bind_port|netcat\s*-e)",
    'Keylogger Routine': r"(GetAsyncKeyState|keyboard\.record|pynput\.keyboard)",
    'Persistence Mechanism': r"(registry\s*run|schtasks\s*/create|cron\s*-e)",
    'Lateral Movement': r"(wmic\s*/node|psexec|net\s+use\s+\\\\)",
    'Phishing Attachment': r"(attachment\s*=\s*['\"].?\.(docx|pdf|zip)['\"]|MIME\s*type\s=\s*['\"].*application/octet-stream)",
    'PowerShell Download': r"(IEX\s*\(New-Object\s*Net\.WebClient\)|Invoke-Expression\s*\(\s*Invoke-WebRequest)",
    'SQL Worm Injection': r"';\s*SHUTDOWN|SELECT\s*.*\s*FROM\s*sysobjects"
}
