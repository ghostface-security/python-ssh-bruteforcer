# Python SSH Brute-Forcer

This Python script is a command-line tool designed to demonstrate and audit the brute-force vulnerability of SSH (Secure Shell) services. It attempts to gain unauthorized access to an SSH server by systematically trying a list of usernames and passwords, highlighting the critical importance of strong credentials and robust security configurations.
⚠️ Disclaimer - IMPORTANT: Ethical Use Only ⚠️

This tool (python-ssh-bruteforcer) is provided strictly for educational, research, and ethical hacking purposes. Its use is limited to testing systems for which you have explicit, prior, and written authorization from the owner.

The creator of this tool is not responsible for any misuse, illegal activities, or damage caused by its deployment or operation. By using this tool, you acknowledge and agree to assume full responsibility for your actions and to comply with all applicable laws and regulations.
Project Purpose & Learning Objectives

This project was developed to:

    Demonstrate SSH Brute-Force Attacks: Illustrate how an attacker can attempt to guess SSH credentials using wordlists.

    Highlight SSH Security Weaknesses: Show the vulnerability of SSH services to brute-force attacks when weak passwords or common usernames are used, or when protective measures like account lockout are absent.

    Reinforce SSH Security Best Practices: Emphasize the critical importance of strong, unique passwords, multi-factor authentication, and robust server configurations.

    Showcase Concurrent Network Interaction: Demonstrate how to programmatically interact with network services like SSH using Python's pexpect library, leveraging ThreadPoolExecutor for efficient, concurrent login attempts.

How It Works

The bruteforcer.py script operates by:

    Parsing Arguments: It accepts command-line arguments for the target SSH server IP/hostname, a password wordlist, and optionally a username wordlist or a single username.

    Reading Wordlists: It reads potential passwords (and usernames, if provided) from the specified text files.

    Concurrent Login Attempts: It uses a ThreadPoolExecutor to manage multiple concurrent login attempts. Each username/password pair is submitted as a separate task to the thread pool, allowing the script to try many combinations in parallel.

    Thread-Safe Progress & Results: Global variables and threading.Lock objects are used to safely track the number of attempts and store any found credentials across multiple threads.

    Reporting Attempts: For each attempt (or periodically for large lists), it provides feedback on the progress.

    Reporting Success: If a successful login occurs, it prints the found username and password and attempts to gracefully shut down other active tasks.

Code Snippet (Core Concurrent Login Logic):

from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import pexpect.pxssh

# Global variables for thread-safe access
found_credentials_lock = Lock()
found_credentials = []
attempt_count_lock = Lock()
current_attempts = 0

def attempt_login(host, username, password):
    """Attempts an SSH login for a single username/password pair."""
    global current_attempts
    with attempt_count_lock:
        current_attempts += 1
        # Progress printing logic here...

    try:
        s = pexpect.pxssh.pxssh(timeout=5) # Initialize pxssh for each thread
        s.login(host, username, password)
        with found_credentials_lock:
            found_credentials.append({'username': username, 'password': password})
            print(f"\n[!!!] VALID CREDENTIALS FOUND: {username}:{password}")
            s.logout()
            return True
    except pexpect.pxssh.ExceptionPxssh:
        pass # Authentication failed
    except Exception as e:
        print(f"[!] An unexpected error occurred for {username}:{password}: {e}")
    return False

# ... (in main function) ...
with ThreadPoolExecutor(max_workers=100) as executor:
    for username in usernames:
        for password in passwords:
            executor.submit(attempt_login, host, username, password)
    # ... logic to wait for futures or break early ...

Installation

To use this script, simply clone the repository:

git clone https://github.com/ghostface-security/python-ssh-bruteforcer.git && cd python-ssh-bruteforcer

This script requires the pexpect library. You can install it using pip:

pip install pexpect

Usage

    Prepare your wordlist files:

        Password Wordlist: Create a text file (e.g., passwords.txt) with one potential password per line.

        Username Wordlist (Optional): Create a text file (e.g., usernames.txt) with one potential username per line.
        (Note: Wordlist files are NOT included in this repository and must be sourced by the user for ethical testing purposes.)

    Run the script from your terminal:

        With a single username:

        python3 bruteforcer.py --target <target_ip> --passlist <path_to_passwords.txt> --username <single_username>

        Example:

        python3 bruteforcer.py -t 192.168.1.100 -p passwords.txt -U admin

        With a username wordlist:

        python3 bruteforcer.py --target <target_ip> --passlist <path_to_passwords.txt> --userlist <path_to_usernames.txt>

        Example:

        python3 bruteforcer.py -t 192.168.1.100 -p passwords.txt -u usernames.txt

Ethical Use Cases

    Personal Server Auditing: Test the strength of SSH credentials on your own servers or devices in a controlled lab environment.

    Educational Demonstrations: Use in a controlled lab to teach about SSH security, brute-force attacks, and the importance of strong authentication.

    Penetration Testing (with Authorization): As part of a professional penetration test, with explicit, prior, and written permission from the client, to identify weak SSH credentials.

Defensive Countermeasures

This tool highlights the critical need for robust SSH security. To protect against SSH brute-force attacks, it is imperative to implement:

    Strong, Unique Passwords: Enforce long, complex, and unique passwords for all SSH accounts.

    Multi-Factor Authentication (MFA): Implement MFA (e.g., TOTP, FIDO2 keys) for SSH logins. This is the most effective defense, as a compromised password alone will not grant access.

    SSH Key-Based Authentication: Prefer SSH key pairs over password authentication. Disable password authentication entirely if possible.

    Account Lockout Policies: Configure your SSH server (e.g., via pam_tally2 or fail2ban) to temporarily or permanently lock accounts after a certain number of failed login attempts.

    Rate Limiting: Use firewall rules or SSH server configurations to limit the number of connection attempts from a single IP address over time.

    Change Default Port: While not a security measure in itself, changing the default SSH port (22) can reduce the volume of automated brute-force attempts from general scanners.

    Use fail2ban: This popular intrusion prevention framework can automatically ban IP addresses that show malicious signs like too many failed login attempts.

License

This project is licensed under the MIT License - see the LICENSE file for details.
