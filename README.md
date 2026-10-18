# 🛡️ AI Security Guard

> An automated code vulnerability and secret leak auditor built for developers and open-source maintainers.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-Backend-lightgrey.svg)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🚀 About the Project
**AI Security Guard** is a lightweight, high-performance static analysis tool designed to scan source code for critical security vulnerabilities, hardcoded cloud secrets, exposed API keys, and unencrypted endpoints before code is deployed or pushed to public repositories.

Built specifically for **Hack Day Jaipur (Hacktoberfest '26)**, this tool bridges the gap between AI development and secure coding practices.

---

## ✨ Key Features
* **Instant Secret Detection:** Automatically catches hardcoded AWS keys, database passwords, and auth tokens.
* **Vulnerability Scanning:** Flags high-risk security flaws like potential SQL injection patterns.
* **Modern Developer Dashboard:** A sleek, responsive dark-themed UI for pasting code, viewing risk scores, and reviewing line-by-line explanations.
* **Lightweight & Modular:** Powered by a fast Python Flask backend and robust regex pattern matching.

---

## 🛠️ Tech Stack
* **Frontend:** HTML5, Tailwind CSS, JavaScript (Vanilla)
* **Backend:** Python, Flask, Flask-CORS
* **Analysis Engine:** Python RegEx & AST (Abstract Syntax Tree)

---

## ⚙️ Getting Started Locally

Follow these steps to run AI Security Guard on your local machine:

### 1. Clone the Repository
```bash
git clone [https://github.com/YOUR-USERNAME/ai-security-guard.git](https://github.com/YOUR-USERNAME/ai-security-guard.git)
cd ai-security-guard
