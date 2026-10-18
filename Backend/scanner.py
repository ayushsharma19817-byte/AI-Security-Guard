import re
import ast

PATTERNS = [
    {
        "name": "Hardcoded AWS / Cloud API Key",
        "severity": "CRITICAL",
        "regex": r"(?i)(AKIA[0-9A-Z]{16})|(api[_-]?key|secret[_-]?key)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]",
        "description": "Exposing private API keys or AWS credentials in code leads to unauthorized access and cloud resource exploitation."
    },
    {
        "name": "Potential SQL Injection",
        "severity": "HIGH",
        "regex": r"(?i)(SELECT|INSERT|UPDATE|DELETE).*?\+\s*[\w_]+|\.execute\s*\(\s*['\"].*?%s|SELECT.*?WHERE.*?\$\{",
        "description": "Unsanitized user inputs concatenated directly into SQL queries allow attackers to manipulate database queries."
    },
    {
        "name": "Hardcoded Credentials / Password",
        "severity": "HIGH",
        "regex": r"(?i)(password|passwd|pwd|db_pass)\s*[:=]\s*['\"][^'\"]+['\"]",
        "description": "Storing plaintext credentials inside source code compromises application security if repository access is shared."
    },
    {
        "name": "Insecure HTTP Protocol",
        "severity": "MEDIUM",
        "regex": r"http://(?!localhost|127\.0\.0\.1)[a-zA-Z0-9.\-]+",
        "description": "Using unencrypted HTTP transmissions leaves traffic vulnerable to Man-In-The-Middle (MITM) eavesdropping."
    }
]

def perform_static_scan(code: str, language: str = "python"):
    issues = []
    
    # 1. Python Syntax & Linter Check (using AST)
    if language.lower() == "python":
        try:
            ast.parse(code)
        except SyntaxError as e:
            issues.append({
                "line": e.lineno or 1,
                "title": "Python Syntax Error / Typo",
                "severity": "CRITICAL",
                "description": f"Syntax Error: {e.msg} (Check for spelling or syntax mistakes like 'impot' instead of 'import').",
                "snippet": e.text.strip() if e.text else code.split('\n')[e.lineno - 1] if e.lineno <= len(code.split('\n')) else "N/A"
            })

    # 2. Security Vulnerability Check (Regex Pattern Matcher)
    lines = code.split('\n')
    for idx, line in enumerate(lines, start=1):
        for pattern in PATTERNS:
            if re.search(pattern["regex"], line):
                issues.append({
                    "line": idx,
                    "title": pattern["name"],
                    "severity": pattern["severity"],
                    "description": pattern["description"],
                    "snippet": line.strip()
                })
                
    return issues