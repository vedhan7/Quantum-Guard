"""
QuantumGuard SSLyze Scanner Module
Wraps SSLyze's Python API for comprehensive TLS/SSL scanning
with quantum-readiness assessment.
"""

import json
import traceback
from datetime import datetime, timezone

from sslyze import (
    Scanner,
    ServerScanRequest,
    ServerNetworkLocation,
    ScanCommandAttemptStatusEnum,
    ServerScanStatusEnum,
)
from sslyze.errors import ServerHostnameCouldNotBeResolved


# ══════════════════════════════════════════════
# QUANTUM VULNERABILITY DATABASE
# ══════════════════════════════════════════════

QUANTUM_VULNERABLE_KEY_EXCHANGES = {
    'ECDH', 'ECDHE', 'RSA', 'DH', 'DHE', 'X25519', 'X448',
    'secp256r1', 'secp384r1', 'secp521r1', 'secp256k1',
    'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1',
}

QUANTUM_SAFE_KEY_EXCHANGES = {
    'ML-KEM', 'Kyber', 'X25519Kyber768',
}

WEAK_CIPHERS = {
    'RC4', 'DES', '3DES', 'DES-CBC3', 'IDEA', 'SEED', 'CAMELLIA',
    'NULL', 'EXPORT', 'anon', 'MD5',
}

CNSA2_REQUIREMENTS = {
    'tls_versions': {'TLSv1.3'},
    'forbidden_key_exchange': {'RSA', 'ECDH', 'ECDHE', 'DH', 'DHE'},
    'required_key_exchange': {'ML-KEM-768', 'ML-KEM-1024'},
    'min_key_size': 3072,
    'allowed_hashes': {'SHA-384', 'SHA-512', 'SHA-3'},
}


def scan_host(hostname, port=443):
    """
    Run a full SSLyze scan against a host and return structured results.
    """
    result = {
        'hostname': hostname,
        'port': port,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'status': 'error',
        'ip_address': None,
        'connectivity': False,
        'scan_duration': None,
        'certificate_info': None,
        'protocol_support': {
            'ssl_2_0': {'supported': False, 'cipher_suites': []},
            'ssl_3_0': {'supported': False, 'cipher_suites': []},
            'tls_1_0': {'supported': False, 'cipher_suites': []},
            'tls_1_1': {'supported': False, 'cipher_suites': []},
            'tls_1_2': {'supported': False, 'cipher_suites': []},
            'tls_1_3': {'supported': False, 'cipher_suites': []},
        },
        'vulnerabilities': {
            'heartbleed': None,
            'ccs_injection': None,
            'robot': None,
            'downgrade': None,
            'compression': None,
            'renegotiation': None,
        },
        'elliptic_curves': {
            'supported': [],
            'rejected': [],
        },
        'mozilla_compliance': None,
        'quantum_score': 0,
        'quantum_assessment': {},
        'recommendations': [],
        'errors': [],
    }

    start_time = datetime.now(timezone.utc)

    try:
        # Create the scan request with all necessary commands
        from sslyze import ScanCommand
        scan_commands = {
            ScanCommand.CERTIFICATE_INFO,
            ScanCommand.SSL_2_0_CIPHER_SUITES,
            ScanCommand.SSL_3_0_CIPHER_SUITES,
            ScanCommand.TLS_1_0_CIPHER_SUITES,
            ScanCommand.TLS_1_1_CIPHER_SUITES,
            ScanCommand.TLS_1_2_CIPHER_SUITES,
            ScanCommand.TLS_1_3_CIPHER_SUITES,
            ScanCommand.HEARTBLEED,
            ScanCommand.OPENSSL_CCS_INJECTION,
            ScanCommand.ROBOT,
            ScanCommand.TLS_FALLBACK_SCSV,
            ScanCommand.TLS_COMPRESSION,
            ScanCommand.SESSION_RENEGOTIATION,
            ScanCommand.ELLIPTIC_CURVES,
        }
        
        server_location = ServerNetworkLocation(
            hostname=hostname,
            port=port
        )
        scan_request = ServerScanRequest(
            server_location=server_location,
            scan_commands=scan_commands
        )

        # Run the scan
        scanner = Scanner()
        scanner.queue_scans([scan_request])

        # Process results
        for server_scan_result in scanner.get_results():
            # Check connectivity
            if server_scan_result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
                result['errors'].append(
                    f"Could not connect to {hostname}:{port}. "
                    f"Error: {server_scan_result.connectivity_error_trace}"
                )
                return result

            result['connectivity'] = True
            result['status'] = 'completed'

            if server_scan_result.server_location.ip_address:
                result['ip_address'] = str(server_scan_result.server_location.ip_address)

            scan_result = server_scan_result.scan_result
            if not scan_result:
                result['errors'].append('Scan completed but no results available')
                return result

            # ── Certificate Information ──
            _extract_certificate_info(scan_result, result)

            # ── Protocol & Cipher Suite Support ──
            _extract_cipher_suites(scan_result, result)

            # ── Vulnerability Checks ──
            _extract_vulnerabilities(scan_result, result)

            # ── Elliptic Curves ──
            _extract_elliptic_curves(scan_result, result)

    except ServerHostnameCouldNotBeResolved:
        result['errors'].append(f"DNS resolution failed for {hostname}")
    except Exception as e:
        result['errors'].append(f"Scan error: {str(e)}")
        result['errors'].append(traceback.format_exc())

    end_time = datetime.now(timezone.utc)
    result['scan_duration'] = round((end_time - start_time).total_seconds(), 2)

    # ── Compute quantum-readiness score ──
    _compute_quantum_score(result)

    # ── Mozilla compliance check ──
    _check_mozilla_compliance(result)

    return result


def _extract_certificate_info(scan_result, result):
    """Extract certificate chain details from scan results."""
    attempt = scan_result.certificate_info
    if attempt.status != ScanCommandAttemptStatusEnum.COMPLETED:
        if attempt.status == ScanCommandAttemptStatusEnum.ERROR:
            result['errors'].append(f"Certificate scan error: {attempt.error_reason}")
        return

    cert_result = attempt.result
    if not cert_result:
        return

    deployments = []
    for deployment in cert_result.certificate_deployments:
        chain = deployment.received_certificate_chain
        if not chain:
            continue

        leaf = chain[0]
        pub_key = leaf.public_key()
        key_type = pub_key.__class__.__name__

        # Get key size
        key_size = None
        try:
            key_size = pub_key.key_size
        except AttributeError:
            pass

        # Build cert info
        cert_info = {
            'subject': leaf.subject.rfc4514_string() if leaf.subject else 'Unknown',
            'issuer': leaf.issuer.rfc4514_string() if leaf.issuer else 'Unknown',
            'serial_number': str(leaf.serial_number),
            'not_before': leaf.not_valid_before_utc.isoformat() if hasattr(leaf, 'not_valid_before_utc') else str(leaf.not_valid_before),
            'not_after': leaf.not_valid_after_utc.isoformat() if hasattr(leaf, 'not_valid_after_utc') else str(leaf.not_valid_after),
            'key_type': key_type,
            'key_size': key_size,
            'signature_algorithm': leaf.signature_hash_algorithm.name if leaf.signature_hash_algorithm else 'Unknown',
            'fingerprint_sha256': leaf.fingerprint(leaf.signature_hash_algorithm).hex() if leaf.signature_hash_algorithm else None,
            'san_dns_names': [],
            'chain': [],
            'trust_stores': {},
        }

        # SAN DNS Names
        try:
            from cryptography.x509 import SubjectAlternativeName, DNSName
            san_ext = leaf.extensions.get_extension_for_class(SubjectAlternativeName)
            cert_info['san_dns_names'] = san_ext.value.get_values_for_type(DNSName)
        except Exception:
            pass

        # Certificate chain
        for cert in chain:
            cert_info['chain'].append(cert.subject.rfc4514_string() if cert.subject else 'Unknown')

        # Trust store results
        for trust_result in deployment.path_validation_results:
            store_name = trust_result.trust_store.name
            was_trusted = trust_result.was_validation_successful
            cert_info['trust_stores'][store_name] = 'Trusted' if was_trusted else 'Not Trusted'

        # OCSP stapling
        cert_info['ocsp_stapling'] = deployment.ocsp_response is not None

        # Must-staple
        cert_info['ocsp_must_staple'] = deployment.leaf_certificate_has_must_staple_extension

        deployments.append(cert_info)

    result['certificate_info'] = deployments


def _extract_cipher_suites(scan_result, result):
    """Extract cipher suite support for each TLS/SSL version."""
    protocol_mapping = {
        'ssl_2_0': 'ssl_2_0_cipher_suites',
        'ssl_3_0': 'ssl_3_0_cipher_suites',
        'tls_1_0': 'tls_1_0_cipher_suites',
        'tls_1_1': 'tls_1_1_cipher_suites',
        'tls_1_2': 'tls_1_2_cipher_suites',
        'tls_1_3': 'tls_1_3_cipher_suites',
    }

    for proto_key, attr_name in protocol_mapping.items():
        attempt = getattr(scan_result, attr_name, None)
        if not attempt or attempt.status != ScanCommandAttemptStatusEnum.COMPLETED:
            continue

        cipher_result = attempt.result
        if not cipher_result:
            continue

        accepted = []
        for cipher in cipher_result.accepted_cipher_suites:
            suite_info = {
                'name': cipher.cipher_suite.name,
                'key_size': cipher.cipher_suite.key_size if hasattr(cipher.cipher_suite, 'key_size') else None,
            }

            # Extract key exchange info if available
            if hasattr(cipher, 'ephemeral_key') and cipher.ephemeral_key:
                eph = cipher.ephemeral_key
                suite_info['key_exchange'] = {
                    'type': eph.__class__.__name__,
                    'size': eph.size if hasattr(eph, 'size') else None,
                    'curve': eph.curve.name if hasattr(eph, 'curve') and hasattr(eph.curve, 'name') else (str(eph.curve) if hasattr(eph, 'curve') and eph.curve is not None else (
                        eph.name if hasattr(eph, 'name') else None
                    )),
                }

            accepted.append(suite_info)

        result['protocol_support'][proto_key] = {
            'supported': len(accepted) > 0,
            'cipher_suites': accepted,
            'total_attempted': len(cipher_result.accepted_cipher_suites) + len(cipher_result.rejected_cipher_suites),
        }


def _extract_vulnerabilities(scan_result, result):
    """Extract vulnerability check results."""
    # Heartbleed
    hb = getattr(scan_result, 'heartbleed', None)
    if hb and hb.status == ScanCommandAttemptStatusEnum.COMPLETED and hb.result:
        result['vulnerabilities']['heartbleed'] = {
            'vulnerable': hb.result.is_vulnerable_to_heartbleed,
            'status': 'VULNERABLE' if hb.result.is_vulnerable_to_heartbleed else 'OK - Not vulnerable',
        }

    # OpenSSL CCS Injection
    ccs = getattr(scan_result, 'openssl_ccs_injection', None)
    if ccs and ccs.status == ScanCommandAttemptStatusEnum.COMPLETED and ccs.result:
        result['vulnerabilities']['ccs_injection'] = {
            'vulnerable': ccs.result.is_vulnerable_to_ccs_injection,
            'status': 'VULNERABLE' if ccs.result.is_vulnerable_to_ccs_injection else 'OK - Not vulnerable',
        }

    # ROBOT
    robot = getattr(scan_result, 'robot', None)
    if robot and robot.status == ScanCommandAttemptStatusEnum.COMPLETED and robot.result:
        robot_enum = robot.result.robot_result
        is_vulnerable = 'NOT_VULNERABLE' not in robot_enum.name
        result['vulnerabilities']['robot'] = {
            'vulnerable': is_vulnerable,
            'status': robot_enum.name,
        }

    # TLS Fallback SCSV (Downgrade)
    fallback = getattr(scan_result, 'tls_fallback_scsv', None)
    if fallback and fallback.status == ScanCommandAttemptStatusEnum.COMPLETED and fallback.result:
        result['vulnerabilities']['downgrade'] = {
            'vulnerable': not fallback.result.supports_fallback_scsv,
            'status': 'OK - TLS_FALLBACK_SCSV supported' if fallback.result.supports_fallback_scsv else 'VULNERABLE - TLS_FALLBACK_SCSV not supported',
        }

    # Compression (CRIME)
    comp = getattr(scan_result, 'tls_compression', None)
    if comp and comp.status == ScanCommandAttemptStatusEnum.COMPLETED and comp.result:
        result['vulnerabilities']['compression'] = {
            'vulnerable': comp.result.supports_compression,
            'status': 'VULNERABLE - Compression enabled (CRIME attack)' if comp.result.supports_compression else 'OK - Compression disabled',
        }

    # Session Renegotiation
    reneg = getattr(scan_result, 'session_renegotiation', None)
    if reneg and reneg.status == ScanCommandAttemptStatusEnum.COMPLETED and reneg.result:
        client_reneg = reneg.result.is_vulnerable_to_client_renegotiation_dos
        secure_reneg = reneg.result.supports_secure_renegotiation
        result['vulnerabilities']['renegotiation'] = {
            'client_renegotiation_vulnerable': client_reneg,
            'secure_renegotiation': secure_reneg,
            'status': (
                'VULNERABLE - Client renegotiation DoS' if client_reneg
                else ('OK - Secure renegotiation supported' if secure_reneg
                      else 'WARNING - Secure renegotiation not supported')
            ),
        }


def _extract_elliptic_curves(scan_result, result):
    """Extract supported elliptic curves."""
    curves = getattr(scan_result, 'elliptic_curves', None)
    if not curves or curves.status != ScanCommandAttemptStatusEnum.COMPLETED or not curves.result:
        return

    result['elliptic_curves']['supported'] = [
        c.name for c in curves.result.supported_curves
    ] if curves.result.supported_curves else []

    result['elliptic_curves']['rejected'] = [
        c.name for c in curves.result.rejected_curves
    ] if curves.result.rejected_curves else []


def _compute_quantum_score(result):
    """Compute a quantum-readiness score (0-100) based on scan results."""
    score = 0
    assessment = {
        'protocol': {'score': 0, 'max': 25, 'details': ''},
        'cipher_strength': {'score': 0, 'max': 20, 'details': ''},
        'key_exchange': {'score': 0, 'max': 25, 'details': ''},
        'certificate': {'score': 0, 'max': 15, 'details': ''},
        'vulnerabilities': {'score': 0, 'max': 15, 'details': ''},
    }
    recommendations = []

    if not result['connectivity']:
        result['quantum_score'] = 0
        result['quantum_assessment'] = assessment
        return

    # ── 1. Protocol Version Scoring (25 pts) ──
    proto = result['protocol_support']

    # Deprecated protocols penalty
    if proto['ssl_2_0']['supported']:
        recommendations.append('CRITICAL: SSL 2.0 is enabled — disable immediately')
    if proto['ssl_3_0']['supported']:
        recommendations.append('CRITICAL: SSL 3.0 is enabled (POODLE) — disable immediately')
    if proto['tls_1_0']['supported']:
        recommendations.append('HIGH: TLS 1.0 is enabled — deprecated, disable')
    if proto['tls_1_1']['supported']:
        recommendations.append('HIGH: TLS 1.1 is enabled — deprecated, disable')

    deprecated = any(proto[p]['supported'] for p in ['ssl_2_0', 'ssl_3_0', 'tls_1_0', 'tls_1_1'])

    if proto['tls_1_3']['supported'] and not deprecated:
        assessment['protocol']['score'] = 25
        assessment['protocol']['details'] = 'TLS 1.3 supported, no deprecated protocols'
    elif proto['tls_1_3']['supported']:
        assessment['protocol']['score'] = 15
        assessment['protocol']['details'] = 'TLS 1.3 supported but deprecated protocols still enabled'
    elif proto['tls_1_2']['supported'] and not deprecated:
        assessment['protocol']['score'] = 15
        assessment['protocol']['details'] = 'TLS 1.2 only — TLS 1.3 recommended for PQC readiness'
        recommendations.append('Enable TLS 1.3 for post-quantum key exchange support')
    elif proto['tls_1_2']['supported']:
        assessment['protocol']['score'] = 8
        assessment['protocol']['details'] = 'TLS 1.2 with deprecated protocols enabled'
    else:
        assessment['protocol']['details'] = 'Only deprecated protocols available'

    # ── 2. Cipher Strength (20 pts) ──
    all_ciphers = []
    for p in proto.values():
        all_ciphers.extend(p.get('cipher_suites', []))

    has_weak = any(
        any(w.lower() in c['name'].lower() for w in WEAK_CIPHERS)
        for c in all_ciphers
    )
    has_256bit = any(
        c.get('key_size') and c['key_size'] >= 256
        for c in all_ciphers
    )

    if has_weak:
        assessment['cipher_strength']['score'] = 5
        assessment['cipher_strength']['details'] = 'Weak cipher suites detected'
        recommendations.append('Remove weak cipher suites (RC4, DES, 3DES, NULL, EXPORT)')
    elif has_256bit:
        assessment['cipher_strength']['score'] = 20
        assessment['cipher_strength']['details'] = 'Strong 256-bit cipher suites available'
    elif all_ciphers:
        assessment['cipher_strength']['score'] = 12
        assessment['cipher_strength']['details'] = '128-bit cipher suites — upgrade to 256-bit for quantum resistance'
        recommendations.append('Prefer AES-256-GCM for Grover\'s algorithm resistance')
    else:
        assessment['cipher_strength']['details'] = 'No cipher suite data'

    # ── 3. Key Exchange Quantum Assessment (25 pts) ──
    kex_types = set()
    for c in all_ciphers:
        kex = c.get('key_exchange', {})
        if kex:
            kex_type = kex.get('curve') or kex.get('type', '')
            kex_types.add(kex_type)
        # Also extract from cipher name
        cipher_name = c['name'].upper()
        if 'ECDHE' in cipher_name or 'ECDH' in cipher_name:
            kex_types.add('ECDHE')
        elif 'DHE' in cipher_name or 'EDH' in cipher_name:
            kex_types.add('DHE')
        elif cipher_name.startswith('TLS_RSA'):
            kex_types.add('RSA')

    has_pqc_kex = any(k in QUANTUM_SAFE_KEY_EXCHANGES for k in kex_types)
    has_vuln_kex = any(
        any(v.lower() in k.lower() for v in QUANTUM_VULNERABLE_KEY_EXCHANGES)
        for k in kex_types if k
    )

    if has_pqc_kex:
        assessment['key_exchange']['score'] = 25
        assessment['key_exchange']['details'] = 'PQC key exchange (ML-KEM/Kyber) detected'
    elif has_vuln_kex:
        assessment['key_exchange']['score'] = 5
        assessment['key_exchange']['details'] = 'Key exchange uses quantum-vulnerable algorithms (ECDHE/RSA/DHE)'
        recommendations.append('Migrate key exchange to ML-KEM (FIPS 203) hybrid mode when available')
    else:
        assessment['key_exchange']['score'] = 0
        assessment['key_exchange']['details'] = 'No key exchange information available'

    # ── 4. Certificate Assessment (15 pts) ──
    certs = result.get('certificate_info', [])
    if certs:
        cert = certs[0]
        key_type = cert.get('key_type', '')
        key_size = cert.get('key_size', 0)

        if 'RSA' in key_type:
            if key_size and key_size >= 4096:
                assessment['certificate']['score'] = 8
                assessment['certificate']['details'] = f'RSA-{key_size} — quantum-vulnerable but large key'
            elif key_size and key_size >= 2048:
                assessment['certificate']['score'] = 5
                assessment['certificate']['details'] = f'RSA-{key_size} — quantum-vulnerable'
            else:
                assessment['certificate']['score'] = 2
                assessment['certificate']['details'] = f'RSA-{key_size} — weak and quantum-vulnerable'
            recommendations.append(f'Certificate uses {key_type} ({key_size}-bit) — migrate to ML-DSA (FIPS 204) when CAs support it')
        elif 'EC' in key_type:
            assessment['certificate']['score'] = 7
            assessment['certificate']['details'] = f'{key_type} — quantum-vulnerable ECC certificate'
            recommendations.append(f'Certificate uses {key_type} — migrate to ML-DSA or SLH-DSA')
        else:
            assessment['certificate']['score'] = 10
            assessment['certificate']['details'] = f'{key_type} certificate'

        # Trust store bonus
        all_trusted = all(v == 'Trusted' for v in cert.get('trust_stores', {}).values())
        if all_trusted and cert.get('trust_stores'):
            assessment['certificate']['score'] = min(assessment['certificate']['score'] + 5, 15)
    else:
        assessment['certificate']['details'] = 'No certificate data'

    # ── 5. Vulnerability Assessment (15 pts) ──
    vulns = result['vulnerabilities']
    vuln_score = 15
    vuln_issues = []

    for vuln_name, vuln_data in vulns.items():
        if vuln_data is None:
            continue
        is_vuln = vuln_data.get('vulnerable', False)
        if isinstance(is_vuln, bool) and is_vuln:
            vuln_score -= 5
            vuln_issues.append(vuln_name)

    assessment['vulnerabilities']['score'] = max(vuln_score, 0)
    if vuln_issues:
        assessment['vulnerabilities']['details'] = f'Vulnerable to: {", ".join(vuln_issues)}'
        recommendations.append(f'Fix vulnerabilities: {", ".join(vuln_issues)}')
    else:
        assessment['vulnerabilities']['details'] = 'No known vulnerabilities detected'

    # ── Tally up ──
    total_score = sum(a['score'] for a in assessment.values())
    result['quantum_score'] = min(total_score, 100)
    result['quantum_assessment'] = assessment
    result['recommendations'] = recommendations


def _check_mozilla_compliance(result):
    """Check results against Mozilla's intermediate TLS configuration."""
    compliance = {
        'profile': 'intermediate',
        'compliant': True,
        'issues': [],
    }

    proto = result['protocol_support']

    # Mozilla intermediate: TLS 1.2 + TLS 1.3 only
    if proto['ssl_2_0']['supported']:
        compliance['issues'].append('SSL 2.0 must be disabled')
    if proto['ssl_3_0']['supported']:
        compliance['issues'].append('SSL 3.0 must be disabled')
    if proto['tls_1_0']['supported']:
        compliance['issues'].append('TLS 1.0 must be disabled')
    if proto['tls_1_1']['supported']:
        compliance['issues'].append('TLS 1.1 must be disabled')
    if not proto['tls_1_2']['supported'] and not proto['tls_1_3']['supported']:
        compliance['issues'].append('At least TLS 1.2 or TLS 1.3 must be supported')

    # Check for weak ciphers
    for p_name, p_data in proto.items():
        for cs in p_data.get('cipher_suites', []):
            name = cs['name'].upper()
            if any(w in name for w in ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'MD5']):
                compliance['issues'].append(f"Weak cipher suite {cs['name']} should be rejected")

    # Certificate lifetime (Mozilla says <= 398 days)
    certs = result.get('certificate_info', [])
    if certs:
        cert = certs[0]
        try:
            not_before = datetime.fromisoformat(cert['not_before'].replace('Z', '+00:00'))
            not_after = datetime.fromisoformat(cert['not_after'].replace('Z', '+00:00'))
            lifespan = (not_after - not_before).days
            if lifespan > 398:
                compliance['issues'].append(
                    f'Certificate lifespan is {lifespan} days, should be <= 398 days'
                )
        except (ValueError, KeyError):
            pass

    compliance['compliant'] = len(compliance['issues']) == 0
    result['mozilla_compliance'] = compliance


def scan_multiple_hosts(targets, timeout=30, on_progress=None):
    """
    Scan multiple hosts concurrently.
    targets: list of dicts with 'hostname' and 'port' keys
    on_progress: callback(hostname, result) called after each host completes
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results = []

    def _scan_one(target):
        hostname = target['hostname']
        port = target.get('port', 443)
        try:
            res = scan_host(hostname, port)
        except Exception as e:
            res = {
                'hostname': hostname,
                'port': port,
                'status': 'error',
                'errors': [str(e)],
                'quantum_score': 0,
                'quantum_assessment': {},
            }
        return hostname, res

    max_workers = min(len(targets), 5)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_scan_one, t): t for t in targets}
        for future in as_completed(futures):
            hostname, res = future.result()
            results.append(res)
            if on_progress:
                on_progress(hostname, res)

    return results

