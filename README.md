# Apache Security Audit Script

## Overview

This Python script performs a **read-only security audit** of your Apache server configuration. It checks for common security best practices and outputs any detected issues both to the console and to a log file. The script is designed to help you identify misconfigurations without making any changes to your server files.

> [!TIP]
> This script is read-only and does not modify any configuration files. You can customize the file paths, security checks, or logging behavior by editing the script directly.

 
 ## Features

- **Server Version Banner Hiding:** Verifies that `ServerTokens Prod` and `ServerSignature Off` are set.
- **Directory Listing:** Ensures directory browsing is disabled (e.g., using `Options -Indexes`).
- **ETag Header:** Checks that `FileETag None` is configured to prevent inode leakage.
- **Non-Privileged Account:** Confirms that Apache is not running as the root user.
- **Directory Permissions:** Validates that critical Apache directories have secure permissions.
- **System Resource Limits:** Audits `/etc/security/limits.conf` for proper resource limit settings.
- **Restricted HTTP Methods:** Ensures that only GET, POST, and OPTIONS are allowed.
- **TRACE Method:** Verifies that the HTTP TRACE method is disabled.
- **Cookie Security Flags:** Checks that cookies are secured with `HttpOnly` and `Secure` flags.
- **Clickjacking Protection:** Confirms that the `X-Frame-Options DENY` header is set.
- **SSI and CGI Checks:** Detects if Server Side Includes (SSI) or CGI are enabled without proper disabling.
- **HTTP Protocol Enforcement:** Verifies that HTTP/1.1 (and HTTP/2) are enforced.
- **Timeout Settings:** Checks that `Timeout 60` is set to mitigate slow HTTP attacks.
- **ModSecurity (WAF):** Audits whether the ModSecurity module is enabled.
- **SSL Configuration:** Ensures SSL is configured to support TLSv1.2 and TLSv1.3 with strong cipher suites.
- **Log File Permissions:** Validates that Apache log files have secure permissions.
- **Root Directory Access:** Checks that access to the root directory is globally restricted.
- **Blocking Sensitive Files:** Ensures access to critical files (e.g., `.htaccess`, `.htpasswd`, `.ini`, `.log`, `.conf`) is blocked.
- **Security Headers:** Verifies that important security headers (such as HSTS and CSP) are set.

## Prerequisites

- **Python 3.x**
- **Rich Library:** For enhanced console output. Install it via pip:

  ```bash
  pip3 install rich

## Usage
Run the audit script using Python:
  ```bash
python3 audite-sec3.py
