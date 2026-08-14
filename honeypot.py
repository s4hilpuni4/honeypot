#!/usr/bin/env python3
"""
Aegis Dynamic Honeypot Service
Author: Senior Cybersecurity Engineer
Description: A lightweight, multi-threaded, thread-safe Python honeypot faking SSH
             and HTTP services, logging connection metadata and payloads in JSON.
"""

import os
import sys
import socket
import threading
import json
from datetime import datetime
import traceback
import argparse

# Thread-safe log lock
log_lock = threading.Lock()

# Global default configurations
DEFAULT_LOG_PATH = "/var/log/honeypot.log"
FALLBACK_LOG_PATH = "./honeypot.log"

SSH_BANNER = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
HTTP_BANNER = (
    b"HTTP/1.1 200 OK\r\n"
    b"Date: %b\r\n"
    b"Server: Apache/2.4.41 (Unix) OpenSSL/1.1.1d PHP/7.4.3\r\n"
    b"Last-Modified: Wed, 08 Jan 2025 23:11:55 GMT\r\n"
    b"ETag: \"3f-59ba4dc0\"\r\n"
    b"Accept-Ranges: bytes\r\n"
    b"Content-Length: 137\r\n"
    b"Connection: close\r\n"
    b"Content-Type: text/html\r\n\r\n"
    b"<!DOCTYPE html>\n<html>\n<head><title>Index of /</title></head>\n"
    b"<body>\n<h1>Index of /</h1>\n<hr>\n<address>Apache/2.4.41 Server</address>\n</body>\n</html>\n"
)

def get_log_filepath(requested_path):
    """
    Determines log file path, falling back to local path if permissions are insufficient.
    """
    try:
        # Check write permissions on requested path or its directory
        target_dir = os.path.dirname(requested_path) or '.'
        if not os.path.exists(target_dir):
            os.makedirs(target_dir, exist_ok=True)
            
        # Try to open the file to verify write access
        with open(requested_path, 'a'):
            pass
        return requested_path
    except (PermissionError, IOError):
        print(f"[!] Warning: Cannot write to '{requested_path}'. Falling back to '{FALLBACK_LOG_PATH}'")
        return FALLBACK_LOG_PATH


def write_log(log_file, src_ip, src_port, dst_port, service, event_type, payload, credentials=None):
    """
    Thread-safely logs threat telemetry to the designated log file.
    """
    log_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "attacker_ip": src_ip,
        "attacker_port": src_port,
        "target_port": dst_port,
        "service": service,
        "event_type": event_type,
        "raw_payload": payload,
    }
    
    if credentials:
        log_entry["credentials"] = credentials

    with log_lock:
        try:
            with open(log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            sys.stderr.write(f"[-] Error writing log to file: {e}\n")


def handle_ssh_client(client_socket, addr, log_file, dst_port):
    """
    Handles incoming simulated SSH connections, logging banners and credentials.
    """
    src_ip, src_port = addr
    print(f"[*] SSH connection from {src_ip}:{src_port}")
    
    try:
        # Write initial connection log
        write_log(log_file, src_ip, src_port, dst_port, "SSH", "connection_established", "TCP Handshake complete")
        
        # Send fake SSH Banner
        client_socket.sendall(SSH_BANNER)
        
        # Read SSH Client Identification / KEX
        client_socket.settimeout(8.0)
        data = client_socket.recv(1024)
        
        if not data:
            client_socket.close()
            return

        payload_str = data.decode('utf-8', errors='replace').strip()
        write_log(log_file, src_ip, src_port, dst_port, "SSH", "client_handshake", payload_str)

        # Simulate authentication prompt guiding brute force requests
        # (This catches interactive script scans / basic login bots)
        client_socket.sendall(b"login as: ")
        username = client_socket.recv(256).decode('utf-8', errors='replace').strip()
        
        client_socket.sendall(b"password: ")
        password = client_socket.recv(256).decode('utf-8', errors='replace').strip()

        credentials = {"username": username, "password": password}
        write_log(
            log_file, 
            src_ip, 
            src_port, 
            dst_port, 
            "SSH", 
            "brute_force_attempt", 
            f"Failed login credentials submitted", 
            credentials
        )
        
        # Send auth failure message
        client_socket.sendall(b"Access denied\r\n")
    except socket.timeout:
        write_log(log_file, src_ip, src_port, dst_port, "SSH", "timeout", "Connection timed out reading handshake")
    except Exception as e:
        write_log(log_file, src_ip, src_port, dst_port, "SSH", "error", f"Socket Exception: {str(e)}")
    finally:
        client_socket.close()


def handle_http_client(client_socket, addr, log_file, dst_port):
    """
    Handles simulated HTTP connections, logging HTTP requests and returning Apache banner.
    """
    src_ip, src_port = addr
    print(f"[*] HTTP connection from {src_ip}:{src_port}")
    
    try:
        # Write connection log
        write_log(log_file, src_ip, src_port, dst_port, "HTTP", "connection_established", "TCP Handshake complete")
        
        client_socket.settimeout(5.0)
        request_data = b""
        while b"\r\n\r\n" not in request_data and len(request_data) < 4096:
            chunk = client_socket.recv(1024)
            if not chunk:
                break
            request_data += chunk
            
        if not request_data:
            client_socket.close()
            return
            
        payload_str = request_data.decode('utf-8', errors='replace')
        
        # Attempt to parse basic details (e.g. Method, Path) for indexing
        first_line = payload_str.split("\n")[0].strip()
        write_log(log_file, src_ip, src_port, dst_port, "HTTP", "http_request", payload_str)
        
        # Format dates for header
        date_gmt = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT').encode('ascii')
        response = HTTP_BANNER % date_gmt
        
        client_socket.sendall(response)
    except socket.timeout:
        pass
    except Exception as e:
        write_log(log_file, src_ip, src_port, dst_port, "HTTP", "error", f"Socket Exception: {str(e)}")
    finally:
        client_socket.close()


def start_honeypot_listener(port, service_type, log_file):
    """
    Binds socket listener to port and dispatches client handlers to separate threads.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(100)
        print(f"[+] Started {service_type} Honeypot listener on port {port}...")
    except PermissionError:
        print(f"[-] Permission denied: Cannot bind to privileged port {port}. Please run with sudo.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Failed to bind to port {port}: {e}")
        sys.exit(1)

    while True:
        try:
            client_sock, addr = server_socket.accept()
            
            # Spawn handler thread based on service type
            if service_type == "SSH":
                target_func = handle_ssh_client
            elif service_type == "HTTP":
                target_func = handle_http_client
            else:
                client_sock.close()
                continue
                
            t = threading.Thread(
                target=target_func, 
                args=(client_sock, addr, log_file, port),
                daemon=True
            )
            t.start()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[-] Listener error on port {port}: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Aegis Dynamic Honeypot Service (SSH/HTTP Simulator)"
    )
    parser.add_argument(
        "--ssh-port", type=int, default=22,
        help="Port to run the SSH simulator on (default: 22)"
    )
    parser.add_argument(
        "--http-port", type=int, default=80,
        help="Port to run the HTTP simulator on (default: 80)"
    )
    parser.add_argument(
        "--log-file", type=str, default=DEFAULT_LOG_PATH,
        help=f"JSON log export filepath (default: {DEFAULT_LOG_PATH})"
    )
    
    args = parser.parse_args()
    log_file = get_log_filepath(args.log_file)
    
    print(f"[*] Log path configured: {log_file}")
    
    # Spawn listeners in background threads
    ssh_thread = threading.Thread(
        target=start_honeypot_listener,
        args=(args.ssh_port, "SSH", log_file),
        daemon=True
    )
    
    http_thread = threading.Thread(
        target=start_honeypot_listener,
        args=(args.http_port, "HTTP", log_file),
        daemon=True
    )
    
    ssh_thread.start()
    http_thread.start()
    
    # Keep the main thread alive to handle KeyboardInterrupt
    try:
        while True:
            ssh_thread.join(timeout=1.0)
            http_thread.join(timeout=1.0)
    except KeyboardInterrupt:
        print("\n[*] Shutting down Honeypot Services...")
        sys.exit(0)


if __name__ == "__main__":
    main()
