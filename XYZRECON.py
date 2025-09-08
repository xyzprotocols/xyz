#!/usr/bin/env python3
"""
XYZRECON: The Ultimate Educational Recon Toolkit
Author: Ruthwik
Purpose: Learn ethical hacking through safe, controlled environments.
LEGAL USE ONLY: Do NOT scan systems without explicit permission.
Default safe target: scanme.nmap.org
"""

import os
import sys
import socket
import requests
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table
import re

# ===================== CONFIG =====================
LOG_DIR = "logs"
DEFAULT_TARGET = "scanme.nmap.org"
MAX_THREADS = 50
HTTP_TIMEOUT = 3
PORT_TIMEOUT = 0.5
DEFAULT_WORDLIST = [
    "admin", "login", "test", "dev", "uploads",
    "backup", "config", "api", "dashboard", "secret"
]
DEFAULT_SUBDOMAINS = [
    "www", "mail", "api", "dev", "test", "admin", "cdn", "blog"
]

console = Console()

# Ensure logs folder exists
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# ===================== UTILITIES =====================
def log(msg, filename="edu_hack.log"):
    """Logs messages to a file with timestamp."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(os.path.join(LOG_DIR, filename), "a") as f:
        f.write(f"[{ts}] {msg}\n")
    console.print(f"[grey58][{ts}][/grey58] {msg}")

def confirm_safe_use(target):
    """Confirms user has permission to scan the target."""
    console.print("[bold red]WARNING![/bold red] Scanning without permission is illegal.")
    console.print(f"Default safe target: [cyan]{DEFAULT_TARGET}[/cyan]")
    console.print(f"You entered: [yellow]{target}[/yellow]")
    ans = input("Type 'yes' to confirm you are authorized: ").strip().lower()
    return ans == "yes"

# ===================== PORT SCANNER =====================
def scan_port(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(PORT_TIMEOUT)
        res = sock.connect_ex((target_ip, port))
        if res == 0:
            banner = ""
            try:
                sock.settimeout(1)
                sock.sendall(b"\r\n")
                banner = sock.recv(1024).decode(errors='ignore').strip()
            except:
                pass
            finally:
                sock.close()
            return port, True, banner
        sock.close()
    except:
        pass
    return port, False, ""

def port_scan():
    target = input(f"Enter target host (default {DEFAULT_TARGET}): ").strip() or DEFAULT_TARGET
    if not confirm_safe_use(target):
        console.print("[bold red]Permission not confirmed. Aborting.[/bold red]")
        return

    try:
        target_ip = socket.gethostbyname(target)
    except Exception as e:
        console.print(f"[red]Could not resolve target: {e}[/red]")
        return

    start_port = int(input("Start port (default 1): ") or "1")
    end_port = int(input("End port (default 1024): ") or "1024")

    console.print(f"\n[bold cyan]Scanning {target} ({target_ip}) ports {start_port}-{end_port}[/bold cyan]\n")
    log(f"Port scan started on {target} ({target_ip}) range {start_port}-{end_port}")

    open_ports = []

    with Progress(SpinnerColumn(), BarColumn(), TextColumn("{task.description}")) as progress:
        task = progress.add_task("Scanning ports...", total=(end_port - start_port + 1))

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {executor.submit(scan_port, target_ip, port): port for port in range(start_port, end_port + 1)}

            for future in as_completed(futures):
                port, status, banner = future.result()
                progress.advance(task)

                if status:
                    open_ports.append((port, banner))
                    log(f"[OPEN] Port {port} Banner: {banner}")

    if open_ports:
        console.print("\n[green]Open Ports Found:[/green]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Port", justify="center")
        table.add_column("Banner/Service")
        for port, banner in open_ports:
            table.add_row(str(port), banner if banner else "Unknown Service")
        console.print(table)
    else:
        console.print("[red]No open ports found in range.[/red]")

# ===================== SUBDOMAIN SCANNER =====================
def check_subdomain(domain, sub):
    url = f"http://{sub}.{domain}"
    try:
        r = requests.head(url, timeout=HTTP_TIMEOUT)
        if r.status_code < 400:
            return url, r.status_code
    except:
        pass
    return url, None

def subdomain_scan():
    domain = input(f"Enter base domain (default {DEFAULT_TARGET}): ").strip() or DEFAULT_TARGET
    if not confirm_safe_use(domain):
        console.print("[bold red]Permission not confirmed. Aborting.[/bold red]")
        return

    console.print(f"\n[bold cyan]Scanning subdomains of {domain}[/bold cyan]")
    log(f"Subdomain scan started on {domain}")

    found = []
    with Progress(SpinnerColumn(), BarColumn(), TextColumn("{task.description}")) as progress:
        task = progress.add_task("Checking subdomains...", total=len(DEFAULT_SUBDOMAINS))

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_subdomain, domain, sub): sub for sub in DEFAULT_SUBDOMAINS}
            for future in as_completed(futures):
                progress.advance(task)
                url, status = future.result()
                if status:
                    found.append((url, status))
                    log(f"[FOUND] {url} Status: {status}")

    if found:
        console.print("\n[green]Active Subdomains:[/green]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Subdomain URL")
        table.add_column("Status Code")
        for url, status in found:
            table.add_row(url, str(status))
        console.print(table)
    else:
        console.print("[red]No active subdomains found with current wordlist.[/red]")

# ===================== DIRECTORY BRUTEFORCER =====================
def check_directory(base_url, path):
    try:
        r = requests.head(f"{base_url}/{path}", timeout=HTTP_TIMEOUT)
        if r.status_code < 400:
            return path, r.status_code
    except:
        pass
    return path, None

def dir_bruteforce():
    base_url = input("Enter target URL (e.g., http://example.com): ").strip()
    if not base_url.startswith("http"):
        console.print("[red]Please include http:// or https://[/red]")
        return

    domain = urlparse(base_url).netloc
    if not confirm_safe_use(domain):
        console.print("[bold red]Permission not confirmed. Aborting.[/bold red]")
        return

    console.print(f"\n[bold cyan]Bruteforcing directories on {base_url}[/bold cyan]")
    log(f"Directory brute force started on {base_url}")

    found = []
    with Progress(SpinnerColumn(), BarColumn(), TextColumn("{task.description}")) as progress:
        task = progress.add_task("Checking directories...", total=len(DEFAULT_WORDLIST))

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_directory, base_url, word): word for word in DEFAULT_WORDLIST}
            for future in as_completed(futures):
                progress.advance(task)
                path, status = future.result()
                if status:
                    found.append((path, status))
                    log(f"[FOUND] /{path} Status: {status}")

    if found:
        console.print("\n[green]Discovered Directories:[/green]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Path")
        table.add_column("Status Code")
        for path, status in found:
            table.add_row("/" + path, str(status))
        console.print(table)
    else:
        console.print("[red]No directories found with current wordlist.[/red]")

# ===================== URL TITLE FETCH =====================
TITLE_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)

def fetch_title(url):
    try:
        r = requests.get(url, timeout=HTTP_TIMEOUT)
        if r.status_code < 400:
            match = TITLE_RE.search(r.text)
            return r.status_code, match.group(1).strip() if match else "No title found"
    except:
        pass
    return None, "Error fetching title"

def title_fetch():
    url = input("Enter target URL (e.g., https://scanme.nmap.org): ").strip()
    if not url.startswith("http"):
        console.print("[red]Please include http:// or https://[/red]")
        return

    domain = urlparse(url).netloc
    if not confirm_safe_use(domain):
        console.print("[bold red]Permission not confirmed. Aborting.[/bold red]")
        return

    status, title = fetch_title(url)
    if status:
        console.print(f"[green]{status}[/green] - Title: [cyan]{title}[/cyan]")
        log(f"[TITLE] {url} {status} {title}")
    else:
        console.print("[red]Failed to fetch page title.[/red]")

# ===================== LOG VIEWER =====================
def view_logs():
    files = os.listdir(LOG_DIR)
    if not files:
        console.print("[yellow]No logs found.[/yellow]")
        return

    console.print("\n[bold cyan]Available Logs:[/bold cyan]")
    for i, fname in enumerate(files, 1):
        console.print(f"{i}. {fname}")

    choice = input("Enter log number to view: ").strip()
    if not choice.isdigit():
        return
    idx = int(choice) - 1
    if 0 <= idx < len(files):
        with open(os.path.join(LOG_DIR, files[idx])) as f:
            console.print(f"\n[bold magenta]{files[idx]}[/bold magenta]\n")
            console.print(f.read())

# ===================== MENU =====================
def menu():
    while True:
        console.print("""
[bold green]=== XYZRECON Toolkit ===[/bold green]
1) Port Scanner
2) Subdomain Scanner
3) Directory Bruteforce
4) Fetch Page Title
5) View Logs
6) Exit
""")
        choice = input("Choose an option: ").strip()

        if choice == "1":
            port_scan()
        elif choice == "2":
            subdomain_scan()
        elif choice == "3":
            dir_bruteforce()
        elif choice == "4":
            title_fetch()
        elif choice == "5":
            view_logs()
        elif choice == "6":
            console.print("[bold green]Exiting. Stay ethical![/bold green]")
            break
        else:
            console.print("[red]Invalid choice. Try again.[/red]")

# ===================== MAIN =====================
if __name__ == "__main__":
    console.print("[bold cyan]XYZRECON: Educational Ethical Hacking Toolkit[/bold cyan]")
    console.print("Use only on systems you own or have permission to test.\n")
    menu()
