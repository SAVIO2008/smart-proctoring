"""
Vercel MongoDB TLS Diagnostic — runs during FastAPI lifespan startup
to gather runtime information. Never prints secrets.

This script is safe to commit temporarily for Vercel deployment diagnostics.
Remove after diagnosis.
"""
import os, sys, ssl, socket, platform

def _run_tls_diagnostics():
    """Gather TLS/runtime diagnostics. Call from lifespan before db_manager.connect()."""
    import logging
    logger = logging.getLogger("tls_diagnostic")

    lines = []
    lines.append("=== TLS Diagnostic ===")

    # 1. Python / OpenSSL
    lines.append(f"Python: {sys.version}")
    lines.append(f"Platform: {platform.platform()}")
    lines.append(f"OpenSSL: {ssl.OPENSSL_VERSION}")
    for attr in ['HAS_TLSv1_2', 'HAS_TLSv1_3']:
        lines.append(f"ssl.{attr}: {getattr(ssl, attr, 'N/A')}")

    # 2. PyMongo
    try:
        import pymongo
        lines.append(f"PyMongo: {pymongo.__version__}")
    except Exception as e:
        lines.append(f"PyMongo: ERROR - {e}")

    # 3. certifi
    try:
        import certifi
        ca_path = certifi.where()
        lines.append(f"certifi path: {ca_path}")
        lines.append(f"certifi file exists: {os.path.exists(ca_path)}")
        if os.path.exists(ca_path):
            lines.append(f"certifi file size: {os.path.getsize(ca_path)} bytes")
    except Exception as e:
        lines.append(f"certifi: ERROR - {e}")
        ca_path = None

    # 4. System CA bundle locations
    for loc in ['/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt',
                '/etc/ssl/ca-bundle.pem', '/etc/pki/tls/cacert.pem']:
        lines.append(f"System CA {loc}: exists={os.path.exists(loc)}")

    # 5. Default SSL context
    try:
        ctx = ssl.create_default_context()
        lines.append(f"Default TLS ctx: OK, min_version={ctx.minimum_version}")
        lines.append(f"Cipher count: {len(ctx.get_ciphers())}")
        # List first few ciphers for reference
        for c in ctx.get_ciphers()[:5]:
            lines.append(f"  cipher: {c['name']}")
    except Exception as e:
        lines.append(f"Default TLS ctx: ERROR - {e}")

    # 6. Environment (masked)
    lines.append(f"DATABASE_MODE: {os.getenv('DATABASE_MODE', 'not set')}")
    mongodb_uri = os.getenv('MONGODB_URI', '')
    lines.append(f"MONGODB_URI configured: {bool(mongodb_uri and mongodb_uri.strip())}")
    lines.append(f"OPENSSL_CONF env: {os.getenv('OPENSSL_CONF', 'not set')}")

    # 7. MongoDB Atlas connectivity tests
    if not mongodb_uri or 'mongodb.net' not in mongodb_uri:
        lines.append("MongoDB Atlas tests: SKIPPED (no Atlas URI configured)")
        report = '\n'.join(lines)
        logger.info(report)
        return report

    # Extract the SRV seed hostname from the URI
    try:
        if '://' in mongodb_uri:
            host_part = mongodb_uri.split('://')[1].split('/')[0]
            if '@' in host_part:
                host_part = host_part.split('@')[1]
            srv_seed = host_part.split(':')[0].split(',')[0]
        else:
            srv_seed = None
    except Exception:
        srv_seed = None

    if not srv_seed:
        lines.append("MongoDB Atlas tests: SKIPPED (could not extract hostname)")
        report = '\n'.join(lines)
        logger.info(report)
        return report

    # Mask the seed for safe logging
    parts = srv_seed.split('.')
    if len(parts) >= 2:
        masked_seed = f"{parts[0][:4]}***.{'.'.join(parts[-2:])}"
    else:
        masked_seed = srv_seed[:4] + "***"
    lines.append(f"SRV seed hostname: {masked_seed}")

    # --- SRV DNS lookup ---
    shard_hosts = []
    try:
        import dns.resolver
        srv_name = f"_mongodb._tcp.{srv_seed}"
        lines.append(f"SRV lookup: {srv_name}")
        answers = dns.resolver.resolve(srv_name, 'SRV')
        for rdata in answers:
            target = str(rdata.target).rstrip('.')
            port = rdata.port
            shard_hosts.append((target, port))
            lines.append(f"  SRV → {target}:{port} (priority={rdata.priority}, weight={rdata.weight})")
        lines.append(f"SRV lookup: SUCCESS ({len(shard_hosts)} hosts)")
    except Exception as e:
        lines.append(f"SRV lookup: FAILED - {type(e).__name__}: {e}")

    if not shard_hosts:
        lines.append("MongoDB Atlas tests: SKIPPED (no shard hosts from SRV)")
        report = '\n'.join(lines)
        logger.info(report)
        return report

    # --- Test the first shard host ---
    test_host, test_port = shard_hosts[0]
    lines.append(f"Testing shard: {test_host}:{test_port}")

    # DNS resolution of actual shard hostname
    try:
        ip = socket.gethostbyname(test_host)
        lines.append(f"  DNS: {test_host} → {ip}")
    except Exception as e:
        lines.append(f"  DNS: FAILED - {type(e).__name__}: {e}")
        report = '\n'.join(lines)
        logger.info(report)
        return report

    # TCP connectivity
    tcp_ok = False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        result = sock.connect_ex((test_host, test_port))
        if result == 0:
            lines.append(f"  TCP {test_host}:{test_port}: REACHABLE")
            tcp_ok = True
        else:
            lines.append(f"  TCP {test_host}:{test_port}: UNREACHABLE (errno={result})")
        sock.close()
    except Exception as e:
        lines.append(f"  TCP test: FAILED - {type(e).__name__}: {e}")

    if not tcp_ok:
        report = '\n'.join(lines)
        logger.info(report)
        return report

    # --- Raw TLS handshake using Python ssl + certifi ---
    lines.append(f"  Attempting TLS handshake (cafile=certifi, server_hostname={test_host})...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect((test_host, test_port))

        ctx = ssl.create_default_context(cafile=ca_path)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        # Set minimum TLS version to 1.2 (Atlas requirement)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        tls_sock = ctx.wrap_socket(sock, server_hostname=test_host)

        # Report negotiated parameters
        cipher = tls_sock.cipher()
        if cipher:
            lines.append(f"  TLS HANDSHAKE: SUCCESS")
            lines.append(f"    Negotiated version: {tls_sock.version()}")
            lines.append(f"    Negotiated cipher: {cipher[0]}")
            lines.append(f"    Cipher protocol: {cipher[1]}")
            lines.append(f"    Cipher bits: {cipher[2]}")
        else:
            lines.append(f"  TLS HANDSHAKE: SUCCESS (no cipher info)")

        # Check peer cert
        cert = tls_sock.getpeercert()
        if cert:
            subject = dict(x[0] for x in cert.get('subject', []))
            lines.append(f"    Peer cert CN: {subject.get('commonName', 'N/A')}")
            lines.append(f"    Peer cert SAN: {[x[1] for x in cert.get('subjectAltName', [])][:3]}")

        tls_sock.close()
    except ssl.SSLError as e:
        lines.append(f"  TLS HANDSHAKE: SSL ERROR")
        lines.append(f"    Exception: {type(e).__name__}")
        lines.append(f"    Message: {e}")
        lines.append(f"    Library: {e.library if hasattr(e, 'library') else 'N/A'}")
        lines.append(f"    Reason: {e.reason if hasattr(e, 'reason') else 'N/A'}")
    except socket.timeout:
        lines.append(f"  TLS HANDSHAKE: TIMEOUT")
    except ConnectionRefusedError:
        lines.append(f"  TLS HANDSHAKE: CONNECTION REFUSED")
    except Exception as e:
        lines.append(f"  TLS HANDSHAKE: ERROR - {type(e).__name__}: {e}")

    report = '\n'.join(lines)
    logger.info(report)
    return report

# For direct execution
if __name__ == '__main__':
    from dotenv import load_dotenv
    load_dotenv(override=True)
    print(_run_tls_diagnostics())