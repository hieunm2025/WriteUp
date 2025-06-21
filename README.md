
**1. Web Attacks Overview**
Web applications frequently interact with the internet using web requests via the HyperText Transfer Protocol (HTTP). HTTP is an application-level protocol for accessing World Wide Web resources, with communications involving a client requesting a resource from a server, which then processes the request and returns the resource. The default port for HTTP is 80, but this can be configured to other ports. HTTP communication is stateless, but HTTP/1.1 allows for TCP socket reuse to improve performance. For secure communication, Hypertext Transfer Protocol Secure (HTTPS) is used, which encrypts data to prevent Man-in-the-Middle (MiTM) attacks, addressing the clear-text data transfer drawback of HTTP. HTTPS relies on TLS (Transport Layer Security) which uses both symmetric and asymmetric cryptography and Public Key Infrastructure (PKI) components like digital certificates and Certificate Authorities (CAs).

**2. Injection Attacks**
Injection attacks occur when unsanitized user input is directly used as part of a command, query, or code. Various types of injection attacks are discussed:

*   **SQL Injection (SQLi)**: Occurs when user input is directly used in an SQL query without proper sanitization.
    *   **Types:** In-band (output directly visible, e.g., Union-Based, Error-Based), Inferential/Blind (output not directly visible, inferred by behavior, e.g., Boolean-based, Time-based), and Out-of-band (data retrieved via a different channel like DNS or HTTP).
    *   **Techniques:** Using comments (`--`, `#`, `/**/`) to modify queries, bypassing filters with logical operators (`AND`, `OR`, `NOT`, `&&`, `||`, `!`), and utilizing specific database functions for data exfiltration (e.g., `xp_cmdshell` for OS command execution in MSSQL, `COPY` for file operations in PostgreSQL).
    *   **Bypasses:** Encoding data (hex, base64) to fit domain name limitations for out-of-band exfiltration, or using concatenation techniques to break up SQL keywords and evade filters.
    *   **Mitigation:** Parameterized queries are highly recommended to prevent SQLi, as they separate the query logic from user-supplied data.

*   **NoSQL Injection (NoSQLi)**: Arises when user input is incorporated into a NoSQL query without proper sanitization.
    *   **Types:** Blind (Boolean-based and Time-based).
    *   **MongoDB Specifics:** Exploits can leverage query operators like `$eq`, `$gt`, `$gte`, `$nin`, `$and`, `$not`, `$nor`, `$or`, `$mod`, `$regex`, and `$where`.
    *   **Bypasses:** String casting without input validation, or manipulating query logic using operators.
    *   **Mitigation:** Input validation (e.g., `preg_match` for allowed characters) and query rewriting can help prevent NoSQLi.

*   **OS Command Injection**: Occurs when user input is directly used as part of an operating system command.
    *   **Operators:** Semicolon (`;`), ampersand (`&`, `&&`), pipe (`|`), sub-shells (` `` `, `$()`). Note that the semicolon does not work with Windows Command Line (CMD) but does with PowerShell.
    *   **Bypasses:** Using new-line characters (`%0a`) or tabs (`%09`) to bypass space filters, `IFS` environment variable, character shifting, and command obfuscation techniques like inserting quotes (`'`, `"`) or backslashes (`\`). Case manipulation and reversing commands are also advanced obfuscation methods. Encoded commands (base64) can also bypass filters.
    *   **Mitigation:** Using built-in functions instead of direct system command execution functions, and always validating and sanitizing user input.

*   **XPath Injection**: Exploits vulnerabilities where user input is unsafely inserted into XPath queries. Operators like `'`, `or`, `and`, `not`, `substring`, `concat`, `count` can be used. Time-based exploits can be used for data exfiltration by observing processing time differences.

*   **LDAP Injection**: Occurs when user input is inserted into Lightweight Directory Access Protocol (LDAP) queries without proper sanitization. LDAP search filters consist of components enclosed in parentheses, with attributes, operands, and values. Operators like `*`, `(`, `)`, `&`, `|`, `!` are used.

*   **Cross-Site Scripting (XSS)**: Occurs when user input containing malicious scripts is displayed on a web page, leading to client-side code execution.
    *   **Types:** Stored/Persistent (input saved and retrieved), Reflected/Non-Persistent (input echoed back directly), and DOM-based (client-side processing).
    *   **Payloads/Contexts:** Script context (`<script>alert('XSS');</script>`), attribute context (`" onmouseover="alert('XSS')"`), HTML context, Anchor Tag context.
    *   **Bypasses:** HTML character entities (e.g., `&lt;`, `&gt;`, `&quot;`, `&apos;`, `&sol;`, `&Tab;`, `&colon;`, `&NewLine;`, `&lpar;`, `&rpar;`, `&plus;`, `&DiacriticalGrave;`) for evasion, double encoding, case sensitivity, and alternative execution sinks (e.g., `eval`, `setTimeout`, `setInterval`, `document.write`, `element.innerHTML`). The `window.name` property and `location.hash` can also be used.
    *   **Impact:** Can lead to cookie stealing, phishing, keylogging, and sensitive data disclosure.

*   **Server-Side Template Injection (SSTI)**: Occurs when user input is embedded unsafely within a template, potentially leading to remote code execution. Identifying the template engine (e.g., Jinja2, Twig, Blade) is crucial, often done by injecting invalid syntax and observing error messages.

*   **XML External Entity (XXE)**: Exploits XML parsers that allow defining external entities, leading to file disclosure, SSRF, or DoS. Parameter entities can bypass standard filters. Out-of-band XXE can exfiltrate data via HTTP requests to an attacker-controlled server.

**3. Authentication Mechanisms**
Attacking authentication mechanisms involves various methods to bypass or compromise user logins.

*   **JSON Web Token (JWT)**: JWTs are used as stateless session tokens. Vulnerabilities arise from weak signing algorithms (e.g., `HS256` with weak keys) or manipulation of unsigned tokens. Tools like `jwt_tool` can analyze and exploit JWTs.
*   **Password Brute-forcing/Dictionary Attacks**: Attempting to guess passwords using common wordlists or all possible character combinations. Can be performed via login pages or API endpoints (e.g., WordPress `xmlrpc.php`).
*   **Multi-Factor Authentication (MFA) Bypass**: Techniques to bypass OTP (One-Time Password) mechanisms, especially if they have predictable lengths, no expiration, or lack rate-limiting/account lockout.
*   **Session Management**: Session tokens can be stateful (server stores user data in memory) or stateless (JWTs). Session puzzling vulnerabilities can occur when session variables are used for multiple processes and can be combined to lead to account takeover.
*   **Weak Security Questions**: Security questions can be insecure if answers are guessable or publicly discoverable.

**4. HTTP Misconfigurations**
Several HTTP-related misconfigurations can lead to vulnerabilities.

*   **HTTP Parameter Pollution (HPP)**: Occurs when an application receives multiple HTTP parameters with the same name, which may cause it to interpret values in unanticipated ways. This can bypass input validation, trigger errors, or modify internal variables.
*   **CRLF Injection**: Involves injecting Carriage Return (`%0d`) and Line Feed (`%0a`) characters to inject new headers or manipulate log entries.
    *   **Log Injection:** Manipulating log files by injecting CRLF sequences into user-supplied parameters.
    *   **HTTP Response Splitting:** Tricking a web server or proxy to interpret a single response as two, potentially leading to web cache poisoning or XSS.
    *   **SMTP Header Injection:** Injecting new SMTP headers into emails sent by the application.
    *   **Mitigation:** URL-encoding user-supplied data before adding it to headers.
*   **Web Cache Poisoning**: Used to distribute an underlying vulnerability (e.g., XSS) to a large number of users by tricking a web cache into storing a malicious response.
    *   **Keyed vs. Unkeyed Parameters:** Parameters that are part of the cache key are "keyed"; others are "unkeyed." Unkeyed parameters can be exploited.
    *   **Cache Busters:** Unique parameter values added to requests to ensure a unique cache key, preventing accidental poisoning of other users' caches.
    *   **Fat GET**: HTTP GET requests that contain a request body, often a web server misconfiguration where the server prefers parameters in the body over the query string.
    *   **Parameter Cloaking**: Creating a discrepancy between the web server and web cache on which parameter to use for the cache key.
    *   **Mitigation:** Proper web cache configuration, not using default settings, and ensuring the web server does not support fat GET requests.
*   **HTTP Request Smuggling (HTTP Desync Attacks)**: Exploits discrepancies between frontend (e.g., reverse proxy, WAF) and backend (web server) systems in parsing HTTP requests, specifically how they determine the length of the request body using `Content-Length (CL)` and `Transfer-Encoding (TE)` headers.
    *   **Types:** CL.TE (frontend uses CL, backend uses TE), TE.TE (both support TE but one is exploitable through obfuscation), and TE.CL (frontend uses TE, backend uses CL).
    *   **HTTP/2 Downgrading:** HTTP/2 requests rewritten to HTTP/1.1 by an intermediary system can introduce smuggling vulnerabilities if the `TE` header has precedence over the added `CL` header in HTTP/1.1.
    *   **Impact:** Mass exploitation of XSS, data theft, WAF bypasses.

**5. File Upload Attacks**
These attacks leverage file upload functionalities to execute malicious code on the server, often by bypassing validation mechanisms.

*   **Web Shells**: Scripts (e.g., PHP, ASP.NET) uploaded to the server to provide remote command execution capabilities, interacting with the backend via the web browser.
*   **Reverse Shells**: Scripts that connect back from the server to an attacker's listener. Tools like `msfvenom` can generate reverse shell scripts for various languages.
*   **Extension Validation Bypass**:
    *   **Blacklisting**: Exploiting incomplete blacklists by using uncommon extensions (e.g., `.phtml`, `.phps`, `.php2`) or case manipulation (e.g., `pHp` on Windows).
    *   **Whitelisting**: Bypassing whitelists by injecting special characters (e.g., null byte `%00`, colon `:`, slash `/`) into the filename to trick the server into processing the malicious file while appearing to be an allowed type.
*   **Content Validation Bypass**: Tricking the server's `Content-Type` header check or actual file content inspection.
*   **Windows 8.3 Filename Convention**: Overwriting existing files or referring to non-existent ones using short filenames with a tilde (`~`).
*   **Apache `.htaccess` Override**: Modifying server behavior by uploading a `.htaccess` file (if allowed) to interpret a custom extension as a PHP script.

**6. Deserialization Attacks**
These attacks involve manipulating serialized objects that are then deserialized by the application, leading to arbitrary code execution or other malicious actions.

*   **Gadget Chains**: Sequences of existing code within the application that are chained together through object deserialization to achieve a malicious outcome (e.g., RCE).
*   **PHP Specifics**: Exploiting `__wakeup()` or `__destruct()` magic methods, and using PHAR archives as a deserialization vector. `phpggc` is a tool for generating PHP deserialization payloads.
*   **.NET Specifics**: Using `ObjectDataProvider` class as a gadget to execute arbitrary commands. `ysoserial.net` can generate payloads for .NET deserialization.
*   **Python Specifics**: YAML deserialization vulnerabilities.
*   **Mitigation**: Switching to safer data formats like JSON and ensuring data integrity checks for serialized objects.

**7. Web Proxies & Tools**
Various tools are essential for web penetration testing.

*   **Web Proxies**: Intercept and modify HTTP/S traffic between a client and server.
    *   **Burp Suite**: A widely used web proxy with features like Repeater (modifying and resending requests), Intruder (fuzzing, enumeration, brute-forcing), Scanner (passive/active vulnerability scanning), and Extender/BApp Store for extensions.
    *   **OWASP ZAP**: An open-source alternative to Burp Suite, offering similar proxy, fuzzer, and scanner capabilities.
*   **Command-Line Tools**:
    *   **cURL**: A command-line tool for sending various types of web requests. Useful for testing HTTP/S requests, user-agents, and handling SSL certificates.
    *   **xcat**: A tool for XPath injection, capable of detecting injections and exfiltrating data.
    *   **msfvenom**: Generates reverse shell scripts.
    *   **NoSQLMap**: Automates discovery and exploitation of NoSQL injection vulnerabilities.
    *   **SQLMap**: Automates discovery and exploitation of SQL injection vulnerabilities for many databases. Supports tamper scripts for payload obfuscation.
    *   **crlfsuite**: A scanner for CRLF injection vulnerabilities.
    *   **Bashfuscator/DOSfuscation**: Tools for obfuscating shell commands on Linux and Windows, respectively.
    *   **WPScan**: Automated WordPress scanner and enumeration tool, identifies outdated themes/plugins and vulnerabilities.
    *   **ffuf, dirbuster, gobuster**: Web fuzzing tools for discovering directories and subdomains.
    *   **httpx**: Gathers information about web services, detects HTTP services on open ports, and filters active subdomains.
    *   **dnsvalidator, shuffledns, subbrute**: DNS enumeration tools for subdomain discovery.
    *   **WhatWeb/Wappalyzer**: Tools for fingerprinting web servers and technologies.
    *   **nuclei**: Scans targets for vulnerabilities based on templates.
    *   **Interactsh/Burp Collaborator**: Tools for detecting out-of-band (OOB) interactions like DNS requests, useful for blind injections.
    *   **WCVS (Web Cache Vulnerability Scanner)**: Helps identify web cache poisoning vulnerabilities, including fat GET and parameter cloaking.

**8. Enumeration & Fingerprinting**
Information gathering is a critical phase, helping to map the attack surface and identify potential entry points.

*   **Subdomain Enumeration**: Active (directly probing, e.g., DNS brute-force) and Passive (relying on publicly available data like search engines, DNS records, certificate transparency logs). Tools: `Sublist3r`, `gau`, `unfurl`, `uro`.
*   **Open Ports/Services Scanning**: Identifying services running on non-standard ports (e.g., `Masscan`, `httpx`).
*   **Directory/Endpoint Fuzzing**: Sending numerous requests to discover accessible directories, files, or endpoints (e.g., `ffuf`, `Dirbuster`). Wordlists like SecLists are crucial.
*   **Web Application Fingerprinting**: Identifying technologies, frameworks, and versions used by inspecting HTTP headers (e.g., `Server`, `X-Powered-By`), file extensions, error messages, meta tags, specific files, and folder structures.

**9. WordPress Specifics**
WordPress, as a popular CMS, has specific enumeration and exploitation techniques.

*   **User Roles**: Five standard roles exist, including Administrator, Editor, and Author. User enumeration is critical for brute-force attacks.
*   **Version and Plugin/Theme Enumeration**: Can be found by reviewing page source (`wp-content/plugins/` paths), `readme.html` file, or using automated tools like WPScan.
*   **Exploitation**: Vulnerable plugins (e.g., Mail Masta) can lead to Local File Inclusion (LFI) or SQL Injection. Admin access can be leveraged to modify themes (e.g., `404.php`) to upload web shells.

**10. General Concepts and Techniques**

*   **Web Requests (HTTP)**: Components of a URL (Host, Port, Path, Query String). Common HTTP methods (GET, POST). HTTP response codes indicate request success (2xx), redirection (3xx), client errors (4xx), or server errors (5xx).
*   **Encoding/Decoding**: URL encoding (percent-encoding) for reserved characters (`%20` for space, `%26` for ampersand, `%23` for pound), HTML encoding (character entities), Base64 encoding. Double encoding can bypass some filters.
*   **Data Exfiltration**: Extracting sensitive data through various channels, including time-based methods, boolean-based responses, or out-of-band techniques.
*   **Fuzzing**: Injecting large amounts of data to find malfunctions or different server responses, often using wordlists. `Wfuzz` is a common tool for this.
*   **Whitebox Pentesting**: Involves access to source code for in-depth analysis and vulnerability identification.
*   **Business Logic Flaws**: Exploiting design errors in the application's functionality, e.g., transaction duplication.
*   **Secure Coding Practices**: Validation and sanitization of user input, using prepared statements (parameterized queries), and limiting the use of functions that execute system commands.
