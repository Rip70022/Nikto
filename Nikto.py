import argparse
import concurrent.futures
import csv
import http.client
import os
import random
import re
import socket
import ssl
import sys
import time
import urllib.parse
from datetime import datetime


class NiktoPython:
    def __init__(self):
        self.version = "1.0"
        self.target = None
        self.port = 80
        self.ssl = False
        self.timeout = 10
        self.threads = 10
        self.output_file = None
        self.verbose = False
        self.user_agent = self.generate_user_agent()
        self.headers = {}
        self.cookies = {}
        self.auth = None
        self.proxy = None
        self.scan_start_time = None
        self.scan_end_time = None
        self.found_vulnerabilities = []
        self.tested_files = 0
        self.positive_files = 0
        self.db_files = self.load_db_files()
        self.db_vulnerabilities = self.load_db_vulnerabilities()

    def display_banner(self):
        banner = """
        ███╗   ██╗██╗██╗  ██╗████████╗ ██████╗     ██████╗ ██╗   ██╗
        ████╗  ██║██║██║ ██╔╝╚══██╔══╝██╔═══██╗    ██╔══██╗╚██╗ ██╔╝
        ██╔██╗ ██║██║█████╔╝    ██║   ██║   ██║    ██████╔╝ ╚████╔╝ 
        ██║╚██╗██║██║██╔═██╗    ██║   ██║   ██║    ██╔═══╝   ╚██╔╝  
        ██║ ╚████║██║██║  ██╗   ██║   ╚██████╔╝    ██║        ██║   
        ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝  ●   ╚═╝        ╚═╝   
                                                                     
        Python Web Vulnerability Scanner v{0}
        Developed by ( https://www.github.com/Rip70022 )
        
        Starting scan at: {1}
        """.format(self.version, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        print(banner)
        
        if self.output_file:
            with open(self.output_file, "a") as f:
                f.write(banner + "\n")

    def generate_user_agent(self):
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        ]
        return random.choice(agents)

    def load_db_files(self):
        return [
            "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env", "/.htaccess", "/web.config",
            "/admin/", "/login", "/wp-login.php", "/administrator/", "/phpmyadmin/",
            "/backup/", "/backup.zip", "/backup.sql", "/db.sql", "/database.sql",
            "/config.php", "/config.inc.php", "/configuration.php", "/settings.php",
            "/setup.php", "/install.php", "/info.php", "/phpinfo.php", "/test.php",
            "/server-status", "/server-info", "/.DS_Store", "/crossdomain.xml",
            "/.well-known/security.txt", "/package.json", "/package-lock.json",
            "/Dockerfile", "/docker-compose.yml", "/Jenkinsfile", "/.gitlab-ci.yml",
            "/.travis.yml", "/composer.json", "/composer.lock", "/yarn.lock",
            "/README.md", "/CHANGELOG.md", "/LICENSE", "/CONTRIBUTING.md"
        ]

    def load_db_vulnerabilities(self):
        return [
            {"pattern": r"<form[^>]*method=[\"']post[\"'][^>]*>", "description": "Possible POST form detected, may require injection testing"},
            {"pattern": r"<input[^>]*type=[\"']password[\"'][^>]*>", "description": "Password field detected, possible authentication point"},
            {"pattern": r"<!--.*?-->", "description": "HTML comment detected, may contain sensitive information"},
            {"pattern": r"phpMyAdmin", "description": "Possible phpMyAdmin installation"},
            {"pattern": r"(?i)sql error|database error|syntax error", "description": "Possible exposed SQL error"},
            {"pattern": r"(?i)exception|stack trace|error on line", "description": "Possible exposed development error"},
            {"pattern": r"(?i)admin|administrator|login|logout|user|username|password", "description": "Possible authentication area"},
            {"pattern": r"(?i)apacheserver at", "description": "Exposed Apache server information"},
            {"pattern": r"(?i)iis\\d+\.\d+", "description": "Exposed IIS server information"}
        ]

    def parse_arguments(self):
        parser = argparse.ArgumentParser(description=f"NiktoPython v{self.version} - Web Security Scanner")
        parser.add_argument("-h", "--host", required=True, help="Target host (example: example.com)")
        parser.add_argument("-p", "--port", type=int, default=80, help="Port (default: 80)")
        parser.add_argument("-ssl", "--ssl", action="store_true", help="Use SSL/TLS")
        parser.add_argument("-t", "--timeout", type=int, default=10, help="Timeout in seconds (default: 10)")
        parser.add_argument("-j", "--threads", type=int, default=10, help="Number of threads (default: 10)")
        parser.add_argument("-o", "--output", help="Output file (example: result.txt)")
        parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
        parser.add_argument("-a", "--user-agent", help="Custom user agent")
        parser.add_argument("-cookie", "--cookie", help="Cookies (format: name=value; name2=value2)")
        parser.add_argument("-auth", "--auth", help="Basic authentication (format: username:password)")
        parser.add_argument("-proxy", "--proxy", help="Use proxy (format: http://proxy:port)")
        
        args = parser.parse_args()
        
        self.target = args.host
        self.port = args.port
        self.ssl = args.ssl
        self.timeout = args.timeout
        self.threads = args.threads
        self.output_file = args.output
        self.verbose = args.verbose
        
        if args.user_agent:
            self.user_agent = args.user_agent
            
        if args.cookie:
            for cookie in args.cookie.split("; "):
                name, value = cookie.split("=", 1)
                self.cookies[name] = value
                
        if args.auth:
            self.auth = args.auth
            
        if args.proxy:
            self.proxy = args.proxy

    def log(self, message, level="INFO"):
        if level == "INFO" or (level == "DEBUG" and self.verbose):
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_message = f"[{timestamp}] [{level}] {message}"
            print(log_message)
            
            if self.output_file:
                with open(self.output_file, "a") as f:
                    f.write(log_message + "\n")

    def make_request(self, path="/"):
        conn = None
        try:
            headers = {
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Connection": "close"
            }
            
            headers.update(self.headers)
            
            if self.cookies:
                headers["Cookie"] = "; ".join([f"{name}={value}" for name, value in self.cookies.items()])
                
            if self.auth:
                import base64
                auth_string = base64.b64encode(self.auth.encode()).decode()
                headers["Authorization"] = f"Basic {auth_string}"
            
            if self.ssl:
                context = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(self.target, self.port, timeout=self.timeout, context=context)
            else:
                conn = http.client.HTTPConnection(self.target, self.port, timeout=self.timeout)
                
            if self.proxy:
                conn.set_tunnel(self.target, self.port)
                
            conn.request("GET", path, headers=headers)
            response = conn.getresponse()
            
            status = response.status
            headers = {h[0]: h[1] for h in response.getheaders()}
            body = response.read().decode('utf-8', errors='ignore')
            
            return {"status": status, "headers": headers, "body": body}
        except Exception as e:
            self.log(f"Error making request to {path}: {str(e)}", "ERROR")
            return None
        finally:
            if conn:
                conn.close()

    def scan_path(self, path):
        self.tested_files += 1
        full_path = urllib.parse.urljoin("/", path)
        
        if self.verbose:
            self.log(f"Scanning: {full_path}", "DEBUG")
            
        response = self.make_request(full_path)
        
        if not response:
            return
            
        status = response["status"]
        headers = response["headers"]
        body = response["body"]
        
        if status in [200, 301, 302, 403]:
            self.positive_files += 1
            self.log(f"[+] Found {full_path} (Code: {status})")
            
            self.check_vulnerability_patterns(full_path, body, headers, status)
            self.check_server_headers(headers)
            
    def check_vulnerability_patterns(self, path, body, headers, status):
        for vuln in self.db_vulnerabilities:
            pattern = vuln["pattern"]
            description = vuln["description"]
            
            if re.search(pattern, body):
                vulnerability = {
                    "path": path,
                    "description": description,
                    "status": status
                }
                
                self.found_vulnerabilities.append(vulnerability)
                self.log(f"[!] Possible vulnerability at {path}: {description}")
                
    def check_server_headers(self, headers):
        interesting_headers = ["server", "x-powered-by", "x-aspnet-version", "x-runtime"]
        
        for header in interesting_headers:
            if header in headers:
                value = headers[header]
                vulnerability = {
                    "path": "HTTP Headers",
                    "description": f"Information header exposed: {header}: {value}",
                    "status": 200
                }
                
                self.found_vulnerabilities.append(vulnerability)
                self.log(f"[!] Sensitive information header: {header}: {value}")

    def scan_target(self):
        self.scan_start_time = datetime.now()
        self.display_banner()
        self.log(f"Starting scan of {self.target}:{self.port} {'(SSL)' if self.ssl else ''}")
        
        protocol = "https" if self.ssl else "http"
        target_url = f"{protocol}://{self.target}:{self.port}"
        self.log(f"Target URL: {target_url}")
        
        try:
            self.log("Checking connectivity with target...")
            server_info = self.make_request("/")
            
            if not server_info:
                self.log("Could not connect to target. Aborting.", "ERROR")
                return
                
            self.log(f"Connected to server: {self.target}")
            
            if "server" in server_info["headers"]:
                self.log(f"Server: {server_info['headers']['server']}")
                
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(self.scan_path, path) for path in self.db_files]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        self.log(f"Error in scan thread: {str(e)}", "ERROR")
                        
        except KeyboardInterrupt:
            self.log("Scan interrupted by user.", "WARNING")
        finally:
            self.scan_end_time = datetime.now()
            self.print_summary()

    def print_summary(self):
        duration = (self.scan_end_time - self.scan_start_time).total_seconds()
        
        self.log("\n" + "=" * 60)
        self.log(f"NiktoPython v{self.version} Scan Summary")
        self.log("=" * 60)
        self.log(f"Target: {self.target}:{self.port} {'(SSL)' if self.ssl else ''}")
        self.log(f"Start: {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        self.log(f"End: {self.scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        self.log(f"Duration: {duration:.2f} seconds")
        self.log(f"Files tested: {self.tested_files}")
        self.log(f"Files found: {self.positive_files}")
        self.log(f"Potential vulnerabilities: {len(self.found_vulnerabilities)}")
        
        if self.found_vulnerabilities:
            self.log("\nPotential vulnerabilities found:")
            for i, vuln in enumerate(self.found_vulnerabilities, 1):
                self.log(f"{i}. {vuln['path']} - {vuln['description']} (Code: {vuln['status']})")
                
        self.log("=" * 60)
        self.log("Scan completed. Thanks for using NiktoPython by github.com/Rip70022")

    def run(self):
        try:
            self.parse_arguments()
            self.scan_target()
        except Exception as e:
            self.log(f"Critical error: {str(e)}", "ERROR")
            sys.exit(1)


if __name__ == "__main__":
    scanner = NiktoPython()
    scanner.run()
