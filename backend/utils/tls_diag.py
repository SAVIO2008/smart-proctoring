"""
Vercel MongoDB TLS Diagnostic — add to backend/app.py lifespan temporarily
to gather runtime information. Never prints secrets.

This script is safe to commit temporarily for Vercel deployment diagnostics.
Remove after diagnosis.
"""
import os, sys, ssl, socket, platform, subprocess

def _run_tls_diagnostics():
    """Gather TLS/runtime diagnostics. Call from lifespan before db_manager.connect()."""
    import logging
    logger = logging.getLogger("tls_diagnostic")
    
    lines = []
    lines.append("=== TLS Diagnostic ===")
    
    # 1. Python version
    lines.append(f"Python: {sys.version}")
    lines.append(f"Platform: {platform.platform()}")
    
    # 2. OpenSSL version
    lines.append(f"OpenSSL: {ssl.OPENSSL_VERSION}")
    
    # 3. PyMongo version
    try:
        import pymongo
        lines.append(f"PyMongo: {pymongo.__version__}")
    except Exception as e:
        lines.append(f"PyMongo: ERROR - {e}")
    
    # 4. certifi
    try:
        import certifi
        ca_path = certifi.where()
        lines.append(f"certifi path: {ca_path}")
        lines.append(f"certifi file exists: {os.path.exists(ca_path)}")
        if os.path.exists(ca_path):
            lines.append(f"certifi file size: {os.path.getsize(ca_path)} bytes")
    except Exception as e:
        lines.append(f"certifi: ERROR - {e}")
    
    # 5. System CA bundle locations
    for loc in ['/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt',
                '/etc/ssl/ca-bundle.pem', '/etc/pki/tls/cacert.pem']:
        lines.append(f"System CA {loc}: exists={os.path.exists(loc)}")
    
    # 6. Default SSL context
    try:
        ctx = ssl.create_default_context()
        lines.append(f"Default TLS ctx: OK, min_version={ctx.minimum_version}")
        # Check what ciphers are available
        lines.append(f"Cipher count: {len(ctx.get_ciphers())}")
    except Exception as e:
        lines.append(f"Default TLS ctx: ERROR - {e}")
    
    # 7. Test TCP connection to MongoDB Atlas (no TLS, just TCP)
    mongodb_uri = os.getenv('MONGODB_URI', '')
    if mongodb_uri and 'mongodb.net' in mongodb_uri:
        # Extract hostname from URI (masked)
        try:
            # Try to resolve the hostname
            # For mongodb+srv:// URIs, extract the host part
            if '://' in mongodb_uri:
                host_part = mongodb_uri.split('://')[1].split('/')[0]
                if '@' in host_part:
                    host_part = host_part.split('@')[1]
                hostname = host_part.split(':')[0].split(',')[0]
                lines.append(f"MongoDB hostname (extracted): {hostname}")
                
                # DNS resolution
                try:
                    ip = socket.gethostbyname(hostname)
                    lines.append(f"DNS resolution: {hostname} → {ip}")
                except Exception as e:
                    lines.append(f"DNS resolution: FAILED - {e}")
                
                # TCP connectivity test (port 27017)
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    result = sock.connect_ex((hostname, 27017))
                    sock.close()
                    if result == 0:
                        lines.append(f"TCP {hostname}:27017: REACHABLE")
                    else:
                        lines.append(f"TCP {hostname}:27017: UNREACHABLE (errno={result})")
                except Exception as e:
                    lines.append(f"TCP test: FAILED - {e}")
                
                # Try a raw TLS handshake with Python's ssl module
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(10)
                    sock.connect((hostname, 27017))
                    ctx = ssl.create_default_context(cafile=certifi.where())
                    ctx.check_hostname = True
                    tls_sock = ctx.wrap_socket(sock, server_hostname=hostname)
                    lines.append(f"TLS handshake to {hostname}:27017: SUCCESS")
                    tls_sock.close()
                except ssl.SSLError as e:
                    lines.append(f"TLS handshake: SSL ERROR - {e}")
                except Exception as e:
                    lines.append(f"TLS handshake: ERROR - {type(e).__name__}: {e}")
        except Exception as e:
            lines.append(f"Hostname extraction: ERROR - {e}")
    else:
        lines.append("MongoDB hostname: not configured or not Atlas (no mongodb.net in URI)")
    
    # 8. Environment (masked)
    lines.append(f"DATABASE_MODE: {os.getenv('DATABASE_MODE', 'not set')}")
    lines.append(f"MONGODB_URI configured: {bool(os.getenv('MONGODB_URI'))}")
    
    # 9. Check for OpenSSL config that might affect things
    openssl_conf = os.getenv('OPENSSL_CONF', 'not set')
    lines.append(f"OPENSSL_CONF env: {openssl_conf}")
    
    # 10. Available TLS versions
    for attr in ['HAS_TLSv1_2', 'HAS_TLSv1_3']:
        lines.append(f"ssl.{attr}: {getattr(ssl, attr, 'N/A')}")
    
    report = '\n'.join(lines)
    logger.info(report)
    return report

# For direct execution
if __name__ == '__main__':
    from dotenv import load_dotenv
    load_dotenv(override=True)
    print(_run_tls_diagnostics())