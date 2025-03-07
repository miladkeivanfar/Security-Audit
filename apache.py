import os
import subprocess
from rich.console import Console
from rich.table import Table
from datetime import datetime

console = Console()
severity_counts = {"High": 0, "Medium": 0, "Low": 0}
log_file = "apache_audit.log"
file_cache = {}  # Cache file contents to avoid redundant reads

def log_issue(issue, severity, solution, reference):
    """Log an issue to the console and append details to a log file."""
    log_entry = (
        f"Issue: {issue}\n"
        f"Severity: {severity}\n"
        f"Solution & Explanation: {solution}\n"
        f"Reference: {reference}\n"
        + "-" * 50 + "\n"
    )
    with open(log_file, "a") as f:
        f.write(log_entry)
    console.print(f"[bold yellow]Issue:[/bold yellow] {issue}")
    console.print(f"[bold red]Severity:[/bold red] {severity}")
    console.print(f"[bold green]Solution & Explanation:[/bold green]\n{solution}")
    console.print(f"[bold blue]Reference:[/bold blue] {reference}")
    console.print("-" * 50)
    sev = severity.split()[0]
    if sev in severity_counts:
        severity_counts[sev] += 1

def get_enabled_lines(file_path):
    """Return a list of non-empty, non-commented lines from a file (cached)."""
    if file_path in file_cache:
        return file_cache[file_path]
    if not os.path.exists(file_path):
        return []
    try:
        with open(file_path, "r") as f:
            lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
        file_cache[file_path] = lines
        return lines
    except Exception as e:
        console.print(f"[bold red]Error reading {file_path}: {e}[/bold red]")
        return []

# --------------------
# Audit Check Functions
# --------------------

def check_server_version_banner():
    config_file = "/etc/apache2/conf-enabled/security.conf"
    lines = get_enabled_lines(config_file)
    if not lines:
        log_issue(
            "Security configuration file for version banner not found",
            "High 🔴",
            ("Ensure the file exists and add the following directives:\n"
             "  ServerTokens Prod\n  ServerSignature Off"),
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )
        return
    if not any("ServerTokens Prod" in line for line in lines):
        log_issue(
            "ServerTokens is not set to Prod",
            "High 🔴",
            "Add 'ServerTokens Prod' to hide detailed server version info.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )
    if not any("ServerSignature Off" in line for line in lines):
        log_issue(
            "ServerSignature is not set to Off",
            "High 🔴",
            "Add 'ServerSignature Off' to prevent the server from revealing version details.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )

def check_directory_listing():
    config_file = "/etc/apache2/apache2.conf"
    lines = get_enabled_lines(config_file)
    if not lines:
        log_issue(
            "Apache main configuration file not found for directory listing check",
            "High 🔴",
            "Ensure /etc/apache2/apache2.conf exists and is configured properly.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )
        return
    if any("Options Indexes" in line for line in lines):
        log_issue(
            "Directory Browsing is enabled",
            "Medium 🟠",
            "Disable directory listing by removing 'Indexes' or using 'Options -Indexes'.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )

def check_etag():
    config_file = "/etc/apache2/apache2.conf"
    lines = get_enabled_lines(config_file)
    if not lines:
        log_issue(
            "Apache main configuration file not found for ETag check",
            "High 🔴",
            "Ensure /etc/apache2/apache2.conf exists.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )
        return
    if not any("FileETag None" in line for line in lines):
        log_issue(
            "ETag header is enabled",
            "Low 🟢",
            "Add 'FileETag None' to disable ETag generation, which may leak inode info.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )

def check_non_privileged_account():
    config_file = "/etc/apache2/apache2.conf"
    lines = get_enabled_lines(config_file)
    if not lines:
        log_issue(
            "Apache main configuration file not found for user account check",
            "High 🔴",
            "Ensure /etc/apache2/apache2.conf exists and is configured for a non-root user.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )
        return
    user_line = next((line for line in lines if line.startswith("User ")), None)
    group_line = next((line for line in lines if line.startswith("Group ")), None)
    if not user_line or not group_line or ("root" in user_line or "root" in group_line):
        log_issue(
            "Apache is running as a privileged account",
            "High 🔴",
            "Configure Apache to run as a non-root user (e.g., www-data) by setting the User and Group directives.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )

def check_directory_permissions():
    expected_permissions = {"/etc/apache2": "750", "/usr/sbin/apache2": "755"}
    for path, expected in expected_permissions.items():
        if os.path.exists(path):
            try:
                perms = oct(os.stat(path).st_mode)[-3:]
                if perms != expected:
                    log_issue(
                        f"Insecure permissions for {path}",
                        "High 🔴",
                        f"Set permissions to {expected} using: sudo chmod {expected} {path}",
                        "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
                    )
            except Exception as e:
                console.print(f"[bold red]Error checking permissions for {path}: {e}[/bold red]")
        else:
            log_issue(
                f"{path} not found",
                "High 🔴",
                f"Ensure {path} exists and is secured.",
                "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
            )

def check_system_settings():
    config_file = "/etc/security/limits.conf"
    lines = get_enabled_lines(config_file)
    if not lines:
        log_issue(
            "System limits configuration file not found",
            "High 🔴",
            "Ensure /etc/security/limits.conf exists and is configured securely.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )
        return
    if not any("nofile" in line for line in lines):
        log_issue(
            "System resource limits may not be properly set",
            "Medium 🟠",
            "Add or modify 'nofile' limits in /etc/security/limits.conf (e.g., '* hard nofile 1024').",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )

def check_http_methods():
    config_file = "/etc/apache2/apache2.conf"
    lines = get_enabled_lines(config_file)
    if not lines:
        log_issue(
            "Apache main configuration file not found for HTTP methods check",
            "High 🔴",
            "Ensure /etc/apache2/apache2.conf exists.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )
        return
    if not any("<LimitExcept GET POST OPTIONS>" in line for line in lines):
        log_issue(
            "Unrestricted HTTP request methods allowed",
            "High 🔴",
            "Restrict HTTP methods by adding a <LimitExcept GET POST OPTIONS> block.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )

def check_trace_method():
    config_file = "/etc/apache2/apache2.conf"
    lines = get_enabled_lines(config_file)
    if not lines:
        log_issue(
            "Apache main configuration file not found for TRACE method check",
            "High 🔴",
            "Ensure /etc/apache2/apache2.conf exists.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )
        return
    if not any("TraceEnable Off" in line for line in lines):
        log_issue(
            "TRACE method is enabled",
            "Medium 🟠",
            "Disable TRACE by adding 'TraceEnable Off' to your configuration.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )

def check_cookie_flags():
    config_file = "/etc/apache2/conf-enabled/security.conf"
    lines = get_enabled_lines(config_file)
    if not lines:
        log_issue(
            "Apache security configuration file not found for cookie flags check",
            "High 🔴",
            "Ensure /etc/apache2/conf-enabled/security.conf exists.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )
        return
    if not any("Header edit Set-Cookie" in line and "HttpOnly;Secure" in line for line in lines):
        log_issue(
            "Cookies do not have HttpOnly and Secure flags set",
            "Medium 🟠",
            "Add 'Header edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure' to secure cookie headers.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )

def check_clickjacking():
    config_file = "/etc/apache2/conf-enabled/security.conf"
    lines = get_enabled_lines(config_file)
    if not lines:
        log_issue(
            "Apache security configuration file not found for clickjacking check",
            "High 🔴",
            "Ensure /etc/apache2/conf-enabled/security.conf exists.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )
        return
    if not any("Header always append X-Frame-Options DENY" in line for line in lines):
        log_issue(
            "Clickjacking protection is not enabled",
            "Medium 🟠",
            "Add 'Header always append X-Frame-Options DENY' to protect against clickjacking.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )

def check_ssi():
    """
    Check for Server Side Includes (SSI) in Apache configuration.
    This function inspects 'Options' directives and flags SSI only if the token 'Includes'
    appears without a preceding dash.
    """
    config_file = "/etc/apache2/apache2.conf"
    lines = get_enabled_lines(config_file)
    if not lines:
        log_issue(
            "Apache main configuration file not found for SSI check",
            "High 🔴",
            "Ensure /etc/apache2/apache2.conf exists.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )
        return
    for line in lines:
        if line.startswith("Options"):
            tokens = line.split()
            for token in tokens:
                # Flag only if 'Includes' appears as a positive directive.
                if token == "Includes":
                    log_issue(
                        "Server Side Includes (SSI) are enabled",
                        "Medium 🟠",
                        "Disable SSI by ensuring 'Includes' is preceded by a dash (i.e. use '-Includes').",
                        "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
                    )
                    return

def check_disable_cgi_ssi():
    """
    Check for CGI and SSI enabling in Apache configuration.
    This function examines 'Options' directives to flag CGI if 'ExecCGI'
    appears without a leading dash.
    """
    config_file = "/etc/apache2/apache2.conf"
    lines = get_enabled_lines(config_file)
    if not lines:
        log_issue(
            "Apache main configuration file not found for CGI/SSI check",
            "High 🔴",
            "Ensure /etc/apache2/apache2.conf exists.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )
        return
    for line in lines:
        if line.startswith("Options"):
            tokens = line.split()
            # Check for CGI enabling (token equals "ExecCGI" without a dash)
            if any(token == "ExecCGI" for token in tokens):
                log_issue(
                    "CGI is enabled",
                    "Medium 🟠",
                    "Disable CGI by ensuring 'ExecCGI' is preceded by a dash (i.e. use '-ExecCGI').",
                    "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
                )
                break

def check_http_1_0():
    config_file = "/etc/apache2/apache2.conf"
    lines = get_enabled_lines(config_file)
    if not lines:
        log_issue(
            "Apache main configuration file not found for HTTP protocol check",
            "High 🔴",
            "Ensure /etc/apache2/apache2.conf exists.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )
        return
    if not any("Protocols" in line and "http/1.1" in line for line in lines):
        log_issue(
            "HTTP/1.0 protocol may be enabled or not explicitly disabled",
            "Low 🟢",
            "Enforce HTTP/1.1 (or higher) by adding 'Protocols h2 http/1.1' to your configuration.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )

def check_timeout():
    config_file = "/etc/apache2/apache2.conf"
    lines = get_enabled_lines(config_file)
    # If the file isn't found or doesn't contain 'Timeout 60', flag it.
    if not lines or not any("Timeout 60" in line for line in lines):
        log_issue(
            "Timeout is not properly configured",
            "Low 🟢",
            "Set 'Timeout 60' to mitigate slow HTTP attacks.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )

def check_mod_security():
    try:
        output = subprocess.getoutput("apachectl -M")
        if "security2_module" not in output:
            log_issue(
                "ModSecurity (WAF) is not enabled",
                "High 🔴",
                "Enable ModSecurity using 'sudo a2enmod security2' and restart Apache.",
                "https://modsecurity.org"
            )
    except Exception as e:
        console.print(f"[bold red]Error checking ModSecurity: {e}[/bold red]")

def check_ssl():
    config_file = "/etc/apache2/mods-enabled/ssl.conf"
    lines = get_enabled_lines(config_file)
    if not lines or not any("SSLProtocol -all +TLSv1.2 +TLSv1.3" in line for line in lines):
        log_issue(
            "Weak SSL configuration",
            "High 🔴",
            "Ensure SSL configuration enables TLSv1.2 and TLSv1.3 with a strong cipher suite.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )

def check_apache_log_files():
    log_dir = "/var/log/apache2"
    if not os.path.exists(log_dir):
        log_issue(
            "Apache log directory not found",
            "High 🔴",
            "Ensure /var/log/apache2 exists and contains log files.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )
        return
    insecure_found = False
    try:
        for filename in os.listdir(log_dir):
            file_path = os.path.join(log_dir, filename)
            if os.path.isfile(file_path):
                perms = oct(os.stat(file_path).st_mode)[-3:]
                if perms != "640":
                    insecure_found = True
                    break
        if insecure_found:
            log_issue(
                "Apache log files may have insecure permissions",
                "Medium 🟠",
                "Set secure permissions using: sudo chmod 640 /var/log/apache2/*.log*",
                "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
            )
    except Exception as e:
        console.print(f"[bold red]Error checking log file permissions: {e}[/bold red]")

def check_deny_root_directory():
    """
    Checks that there is a <Directory /> block that contains 'Require all denied'.
    This function scans the file line by line, turning on block parsing when it
    encounters <Directory /> and searching until </Directory>.
    """
    config_file = "/etc/apache2/apache2.conf"
    lines = get_enabled_lines(config_file)
    if not lines:
        log_issue(
            "Apache main configuration file not found for root directory check",
            "High 🔴",
            "Ensure /etc/apache2/apache2.conf exists.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )
        return

    in_block = False
    has_deny = False
    for line in lines:
        if "<Directory />" in line:
            in_block = True
        elif in_block and "</Directory>" in line:
            if has_deny:
                return  # Valid block found
            in_block = False
            has_deny = False
        elif in_block:
            if "Require all denied" in line:
                has_deny = True
    if not has_deny:
        log_issue(
            "Access to the root directory is not globally restricted",
            "High 🔴",
            ("Add a block to deny access to the root directory:\n"
             "<Directory \"/\">\n    Require all denied\n</Directory>"),
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )

def check_block_sensitive_files():
    config_file = "/etc/apache2/apache2.conf"
    lines = get_enabled_lines(config_file)
    if not lines:
        log_issue(
            "Apache main configuration file not found for sensitive files check",
            "High 🔴",
            "Ensure /etc/apache2/apache2.conf exists.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )
        return
    if not any("<FilesMatch \"^(\\.htaccess|\\.htpasswd|\\.ini|\\.log|\\.conf)$\">" in line for line in lines):
        log_issue(
            "Access to sensitive files is not blocked",
            "High 🔴",
            "Add a FilesMatch block to restrict access to critical files.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )

def check_disable_cgi_ssi():
    """
    Checks that CGI is disabled by ensuring that any Options directive does not
    include the positive token 'ExecCGI'. It assumes that a disabled CGI directive
    would appear as '-ExecCGI'.
    """
    config_file = "/etc/apache2/apache2.conf"
    lines = get_enabled_lines(config_file)
    if not lines:
        log_issue(
            "Apache main configuration file not found for CGI/SSI check",
            "High 🔴",
            "Ensure /etc/apache2/apache2.conf exists.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )
        return
    for line in lines:
        if line.startswith("Options"):
            tokens = line.split()
            if any(token == "ExecCGI" for token in tokens):
                log_issue(
                    "CGI is enabled",
                    "Medium 🟠",
                    "Disable CGI by ensuring 'ExecCGI' is preceded by a dash (i.e. use '-ExecCGI').",
                    "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
                )
                break

def check_security_headers():
    config_file = "/etc/apache2/conf-enabled/security.conf"
    lines = get_enabled_lines(config_file)
    if not lines:
        log_issue(
            "Apache security configuration file not found for security headers check",
            "High 🔴",
            "Ensure /etc/apache2/conf-enabled/security.conf exists.",
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )
        return
    if not (any("Strict-Transport-Security" in line for line in lines) and 
            any("Content-Security-Policy" in line for line in lines)):
        log_issue(
            "Security headers are not properly configured",
            "High 🔴",
            ("Add directives such as:\n"
             "  Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"\n"
             "  Header always set Content-Security-Policy \"default-src https:; script-src 'self'\""),
            "https://www.aptive.co.uk/blog/apacheconfig-security-hardening/"
        )

# --------------------
# Main Audit Function
# --------------------

def run_audit():
    # Clear previous log and cache
    open(log_file, "w").close()
    file_cache.clear()
    console.print(f"[bold cyan]🔍 Running Apache Security Audit - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/bold cyan]\n")
    
    checks = [
        check_server_version_banner,
        check_directory_listing,
        check_etag,
        check_non_privileged_account,
        check_directory_permissions,
        check_system_settings,
        check_http_methods,
        check_trace_method,
        check_cookie_flags,
        check_clickjacking,
        check_ssi,
        check_disable_cgi_ssi,
        check_http_1_0,
        check_timeout,
        check_mod_security,
        check_ssl,
        check_apache_log_files,
        check_deny_root_directory,
        check_block_sensitive_files,
        check_security_headers
    ]
    
    for check in checks:
        check()
    
    console.print("\n[bold cyan]📊 Security Audit Summary:[/bold cyan]\n")
    summary_table = Table(show_header=True, header_style="bold cyan")
    summary_table.add_column("Severity", justify="center", style="bold")
    summary_table.add_column("Count", justify="center", style="bold green")
    summary_table.add_row("High 🔴", str(severity_counts["High"]))
    summary_table.add_row("Medium 🟠", str(severity_counts["Medium"]))
    summary_table.add_row("Low 🟢", str(severity_counts["Low"]))
    console.print(summary_table)
    console.print(f"[bold green]✔ Audit results logged to {log_file}[/bold green]")

if __name__ == "__main__":
    run_audit()
