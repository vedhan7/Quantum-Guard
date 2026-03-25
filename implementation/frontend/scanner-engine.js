/**
 * QuantumGuard Scanner Engine
 * Core scanning library for quantum-vulnerable cryptography detection.
 * Works in both browser and Node.js environments.
 */
const Scanner = (function() {
  'use strict';

  // ═══════════════════════════════════════════════════════
  // CRYPTO PATTERN DATABASE — Quantum-Vulnerable Algorithms
  // ═══════════════════════════════════════════════════════
  const VULN_PATTERNS = [
    // ── RSA ──
    { id: 'RSA', algorithm: 'RSA', type: 'asymmetric', severity: 'critical', quantumVuln: true,
      patterns: [
        /\bRSA[-_]?(OAEP|PSS|PKCS1|PKCS|2048|3072|4096)?\b/gi,
        /\bRSAKeyPairGenerator\b/gi, /\bRSA_generate_key\b/gi,
        /\bCrypto\.RSA\b/gi, /\bRSAPublicKey\b/gi, /\bRSAPrivateKey\b/gi,
        /\bcrypto\.generateKeyPair\s*\(\s*['"]rsa['"]/gi,
        /\bRSA_sign\b|\bRSA_verify\b|\bRSA_encrypt\b|\bRSA_decrypt\b/gi,
        /\brsa\.GenerateKey\b/gi, /\bNewSignerVerifier.*rsa/gi,
        /from\s+['"].*rsa['"]/gi, /import\s+['"].*rsa['"]/gi,
      ],
      recommendation: 'Migrate to ML-KEM (FIPS 203) for key encapsulation or ML-DSA (FIPS 204) for signatures',
      pqcAlternative: 'ML-KEM / ML-DSA'
    },
    // ── ECDSA / ECDH / ECC ──
    { id: 'ECC', algorithm: 'ECDSA/ECDH/ECC', type: 'asymmetric', severity: 'critical', quantumVuln: true,
      patterns: [
        /\bECDSA\b/gi, /\bECDH\b/gi, /\bEC[-_]?KEY\b/gi,
        /\belliptic[-_]?curve/gi, /\bsecp256[kr]1\b/gi, /\bsecp384r1\b/gi,
        /\bP-256\b|\bP-384\b|\bP-521\b/g,
        /\bcurve25519\b/gi, /\bed25519\b/gi, /\bx25519\b/gi,
        /\bEC_KEY_new\b|\bEC_KEY_generate_key\b/gi,
        /\bKeyPairGenerator\.getInstance\s*\(\s*['"]EC['"]/gi,
        /\bcrypto\.generateKeyPair\s*\(\s*['"]ec['"]/gi,
        /\bcrypto\.ECDH\b/gi, /\becdsa\.Sign\b/gi,
      ],
      recommendation: 'Migrate to ML-DSA (FIPS 204) for signatures, ML-KEM (FIPS 203) for key exchange',
      pqcAlternative: 'ML-DSA / ML-KEM'
    },
    // ── DSA ──
    { id: 'DSA', algorithm: 'DSA', type: 'asymmetric', severity: 'critical', quantumVuln: true,
      patterns: [
        /\bDSA[-_]?(sign|verify|generate|key)?\b/gi,
        /\bKeyPairGenerator\.getInstance\s*\(\s*['"]DSA['"]/gi,
        /\bdsa\.GenerateKey\b/gi,
      ],
      recommendation: 'Migrate to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)',
      pqcAlternative: 'ML-DSA / SLH-DSA'
    },
    // ── Diffie-Hellman ──
    { id: 'DH', algorithm: 'Diffie-Hellman', type: 'asymmetric', severity: 'critical', quantumVuln: true,
      patterns: [
        /\bDiffie[-_]?Hellman\b/gi, /\bDH_generate_key\b/gi,
        /\bcrypto\.createDiffieHellman\b/gi, /\bcrypto\.DH\b/gi,
        /\bDHParameterSpec\b/gi, /\bDH_compute_key\b/gi,
      ],
      recommendation: 'Migrate to ML-KEM (FIPS 203) for key exchange',
      pqcAlternative: 'ML-KEM'
    },
    // ── MD5 ──
    { id: 'MD5', algorithm: 'MD5', type: 'hash', severity: 'critical', quantumVuln: false,
      patterns: [
        /\bMD5\b/g, /\bmd5\s*\(/gi, /\bEVP_md5\b/gi,
        /\.createHash\s*\(\s*['"]md5['"]/gi,
        /MessageDigest\.getInstance\s*\(\s*['"]MD5['"]/gi,
        /\bhashlib\.md5\b/gi,
      ],
      recommendation: 'Replace with SHA-256 or SHA-3. MD5 is cryptographically broken regardless of quantum.',
      pqcAlternative: 'SHA-256 / SHA-3'
    },
    // ── SHA-1 ──
    { id: 'SHA1', algorithm: 'SHA-1', type: 'hash', severity: 'high', quantumVuln: false,
      patterns: [
        /\bSHA[-_]?1\b/gi, /\bsha1\s*\(/gi, /\bEVP_sha1\b/gi,
        /\.createHash\s*\(\s*['"]sha1['"]/gi,
        /MessageDigest\.getInstance\s*\(\s*['"]SHA-1['"]/gi,
        /\bhashlib\.sha1\b/gi,
      ],
      recommendation: 'Migrate to SHA-256 or SHA-3. SHA-1 has known collision attacks.',
      pqcAlternative: 'SHA-256 / SHA-3'
    },
    // ── 3DES / Triple DES ──
    { id: '3DES', algorithm: '3DES / Triple-DES', type: 'symmetric', severity: 'high', quantumVuln: false,
      patterns: [
        /\b3DES\b/gi, /\bTriple[-_]?DES\b/gi, /\bDESede\b/gi,
        /\bEVP_des_ede3\b/gi, /\bDES[-_]EDE3\b/gi,
        /Cipher\.getInstance\s*\(\s*['"]DESede/gi,
      ],
      recommendation: 'Migrate to AES-256-GCM. 3DES has effective key strength <112 bits.',
      pqcAlternative: 'AES-256-GCM'
    },
    // ── DES ──
    { id: 'DES', algorithm: 'DES', type: 'symmetric', severity: 'critical', quantumVuln: false,
      patterns: [
        /\bDES[-_]?(cbc|ecb|cfb|ofb)\b/gi,
        /\bEVP_des_cbc\b|\bEVP_des_ecb\b/gi,
        /Cipher\.getInstance\s*\(\s*['"]DES\b/gi,
      ],
      recommendation: 'DES uses 56-bit key and is trivially broken. Migrate to AES-256.',
      pqcAlternative: 'AES-256'
    },
    // ── RC4 ──
    { id: 'RC4', algorithm: 'RC4 / ARC4', type: 'symmetric', severity: 'critical', quantumVuln: false,
      patterns: [
        /\bRC4\b/gi, /\bARC4\b/gi, /\bARCFOUR\b/gi,
        /\bEVP_rc4\b/gi,
        /Cipher\.getInstance\s*\(\s*['"]RC4/gi,
      ],
      recommendation: 'RC4 is broken. Migrate to AES-256-GCM or ChaCha20-Poly1305.',
      pqcAlternative: 'AES-256-GCM / ChaCha20'
    },
    // ── Blowfish ──
    { id: 'BLOWFISH', algorithm: 'Blowfish', type: 'symmetric', severity: 'warning', quantumVuln: false,
      patterns: [
        /\bBlowfish\b/gi, /\bBF[-_]?(cbc|ecb)\b/gi,
        /\bEVP_bf_cbc\b/gi,
      ],
      recommendation: 'Blowfish has 64-bit block and is vulnerable to Sweet32. Migrate to AES-256.',
      pqcAlternative: 'AES-256'
    },
    // ── AES with weak key sizes ──
    { id: 'AES-128', algorithm: 'AES-128', type: 'symmetric', severity: 'warning', quantumVuln: true,
      patterns: [
        /\bAES[-_]?128\b/gi,
        /aes[-_]128[-_]?(cbc|ecb|gcm|ctr)/gi,
      ],
      recommendation: 'AES-128 provides only 64-bit security against Grover\'s algorithm. Upgrade to AES-256.',
      pqcAlternative: 'AES-256'
    },
  ];

  // ═══════════════════════════════════════════════════════
  // PQC-SAFE PATTERNS — Quantum-Resistant Algorithms
  // ═══════════════════════════════════════════════════════
  const SAFE_PATTERNS = [
    { id: 'ML-KEM', algorithm: 'ML-KEM (FIPS 203)', type: 'kem',
      patterns: [/\bML[-_]?KEM\b/gi, /\bKyber\b/gi, /\bCRYSTALS[-_]?Kyber\b/gi, /\bFIPS[-_]?203\b/gi] },
    { id: 'ML-DSA', algorithm: 'ML-DSA (FIPS 204)', type: 'signature',
      patterns: [/\bML[-_]?DSA\b/gi, /\bDilithium\b/gi, /\bCRYSTALS[-_]?Dilithium\b/gi, /\bFIPS[-_]?204\b/gi] },
    { id: 'SLH-DSA', algorithm: 'SLH-DSA (FIPS 205)', type: 'signature',
      patterns: [/\bSLH[-_]?DSA\b/gi, /\bSPHINCS\+?\b/gi, /\bFIPS[-_]?205\b/gi] },
    { id: 'AES-256', algorithm: 'AES-256', type: 'symmetric',
      patterns: [/\bAES[-_]?256\b/gi, /aes[-_]256[-_]?(gcm|cbc|ctr)/gi] },
    { id: 'SHA-256', algorithm: 'SHA-256', type: 'hash',
      patterns: [/\bSHA[-_]?256\b/gi, /\bSHA[-_]?384\b/gi, /\bSHA[-_]?512\b/gi] },
    { id: 'SHA-3', algorithm: 'SHA-3', type: 'hash',
      patterns: [/\bSHA[-_]?3\b/gi, /\bSHAKE[-_]?(128|256)\b/gi] },
    { id: 'ChaCha20', algorithm: 'ChaCha20-Poly1305', type: 'symmetric',
      patterns: [/\bChaCha20\b/gi, /\bPoly1305\b/gi, /\bXChaCha\b/gi] },
  ];

  // ═══════════════════════════════════════════════════════
  // CRYPTO DEPENDENCY DATABASE
  // ═══════════════════════════════════════════════════════
  const VULN_DEPS = {
    // npm packages
    'node-rsa': { lang: 'npm', algo: 'RSA', severity: 'critical', alt: 'liboqs-node, crystals-kyber' },
    'jsrsasign': { lang: 'npm', algo: 'RSA/ECDSA', severity: 'critical', alt: 'Use PQC wrappers via liboqs' },
    'node-forge': { lang: 'npm', algo: 'RSA/DES/RC4/MD5', severity: 'critical', alt: 'Audit usage; migrate RSA to PQC' },
    'crypto-js': { lang: 'npm', algo: 'DES/3DES/MD5/SHA-1/AES', severity: 'warning', alt: 'Use node:crypto with AES-256-GCM' },
    'md5': { lang: 'npm', algo: 'MD5', severity: 'critical', alt: 'Use SHA-256 via node:crypto' },
    'sha1': { lang: 'npm', algo: 'SHA-1', severity: 'high', alt: 'Use SHA-256 via node:crypto' },
    'bcryptjs': { lang: 'npm', algo: 'Blowfish', severity: 'info', alt: 'Acceptable for password hashing' },
    'elliptic': { lang: 'npm', algo: 'ECDSA/ECDH', severity: 'critical', alt: 'Migrate to ML-DSA/ML-KEM' },
    'secp256k1': { lang: 'npm', algo: 'ECDSA (secp256k1)', severity: 'critical', alt: 'ML-DSA (FIPS 204)' },
    'tweetnacl': { lang: 'npm', algo: 'Curve25519/Ed25519', severity: 'critical', alt: 'ML-DSA / ML-KEM' },
    'libsodium-wrappers': { lang: 'npm', algo: 'Curve25519/Ed25519/XSalsa20', severity: 'warning', alt: 'Review XSalsa20' },
    'openpgp': { lang: 'npm', algo: 'RSA/ECDSA/ECDH', severity: 'critical', alt: 'Requires PQC migration plan' },
    // Python packages
    'pycryptodome': { lang: 'pip', algo: 'RSA/DSA/ECC/DES/ARC4', severity: 'critical', alt: 'liboqs-python for PQC' },
    'cryptography': { lang: 'pip', algo: 'RSA/ECC/DH', severity: 'warning', alt: 'Audit usage; has some PQC support' },
    'rsa': { lang: 'pip', algo: 'RSA', severity: 'critical', alt: 'liboqs-python' },
    'ecdsa': { lang: 'pip', algo: 'ECDSA', severity: 'critical', alt: 'liboqs-python ML-DSA' },
    'hashlib': { lang: 'pip', algo: 'MD5/SHA-1 available', severity: 'info', alt: 'Avoid md5()/sha1(); use sha256()' },
    'pyOpenSSL': { lang: 'pip', algo: 'RSA/ECC/DH', severity: 'warning', alt: 'Audit cipher configuration' },
    // Java
    'bcprov-jdk': { lang: 'maven', algo: 'RSA/ECC/DSA', severity: 'warning', alt: 'BouncyCastle pqc-jdk for PQC' },
    'jasypt': { lang: 'maven', algo: 'DES/PBE', severity: 'high', alt: 'Use AES-256-GCM via JCA' },
    // Go
    'crypto/rsa': { lang: 'go', algo: 'RSA', severity: 'critical', alt: 'cloudflare/circl for PQC' },
    'crypto/ecdsa': { lang: 'go', algo: 'ECDSA', severity: 'critical', alt: 'cloudflare/circl ML-DSA' },
    'crypto/dsa': { lang: 'go', algo: 'DSA', severity: 'critical', alt: 'cloudflare/circl' },
    'crypto/des': { lang: 'go', algo: 'DES/3DES', severity: 'high', alt: 'crypto/aes with 256-bit key' },
    'crypto/rc4': { lang: 'go', algo: 'RC4', severity: 'critical', alt: 'crypto/aes or chacha20poly1305' },
    'crypto/md5': { lang: 'go', algo: 'MD5', severity: 'critical', alt: 'crypto/sha256' },
    'crypto/sha1': { lang: 'go', algo: 'SHA-1', severity: 'high', alt: 'crypto/sha256' },
  };

  // ═══════════════════════════════════════════════════════
  // CNSA 2.0 REQUIREMENTS
  // ═══════════════════════════════════════════════════════
  const CNSA2_REQUIREMENTS = {
    keyExchange: ['ML-KEM-768', 'ML-KEM-1024', 'Kyber-768', 'Kyber-1024'],
    signatures: ['ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128s', 'SLH-DSA-SHA2-192s'],
    symmetric: ['AES-256'],
    hash: ['SHA-384', 'SHA-512', 'SHA-3-256', 'SHA-3-384'],
    tlsVersion: ['TLSv1.3'],
    forbidden: ['RSA', 'ECDSA', 'ECDH', 'DH', 'DSA', 'MD5', 'SHA-1', '3DES', 'RC4', 'DES']
  };

  // SSLyze API backend URL — auto-switches between production and local dev
  // Replace YOUR_RENDER_APP_NAME with your actual Render service name after deploying
  const SSLYZE_API_URL = window.location.hostname === 'localhost'
    ? 'http://localhost:5001'
    : 'https://quantum-guard.onrender.com';

  // ═══════════════════════════════════════════════════════
  // 1. CRYPTOSCAN — Source Code Analysis
  // ═══════════════════════════════════════════════════════
  function scanSource(filename, content) {
    const findings = [];
    const safeFindings = [];
    const lines = content.split('\n');

    // Check for vulnerable patterns
    VULN_PATTERNS.forEach(pattern => {
      pattern.patterns.forEach(regex => {
        lines.forEach((line, lineNum) => {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) return;
          const matches = line.match(regex);
          if (matches) {
            // Avoid duplicate findings on same line for same algorithm
            const existing = findings.find(f => f.line === lineNum + 1 && f.algorithmId === pattern.id);
            if (!existing) {
              findings.push({
                algorithmId: pattern.id,
                algorithm: pattern.algorithm,
                type: pattern.type,
                severity: pattern.severity,
                quantumVulnerable: pattern.quantumVuln,
                file: filename,
                line: lineNum + 1,
                code: trimmed.substring(0, 120),
                match: matches[0],
                recommendation: pattern.recommendation,
                pqcAlternative: pattern.pqcAlternative
              });
            }
          }
        });
      });
    });

    // Check for PQC-safe patterns
    SAFE_PATTERNS.forEach(pattern => {
      pattern.patterns.forEach(regex => {
        lines.forEach((line, lineNum) => {
          if (line.match(regex)) {
            const existing = safeFindings.find(f => f.line === lineNum + 1 && f.id === pattern.id);
            if (!existing) {
              safeFindings.push({
                id: pattern.id,
                algorithm: pattern.algorithm,
                type: pattern.type,
                file: filename,
                line: lineNum + 1,
                code: line.trim().substring(0, 120)
              });
            }
          }
        });
      });
    });

    return { findings, safeFindings };
  }

  function scanMultipleFiles(files) {
    const allFindings = [];
    const allSafe = [];
    files.forEach(f => {
      const result = scanSource(f.name, f.content);
      allFindings.push(...result.findings);
      allSafe.push(...result.safeFindings);
    });

    const summary = {
      totalFiles: files.length,
      totalFindings: allFindings.length,
      totalSafe: allSafe.length,
      critical: allFindings.filter(f => f.severity === 'critical').length,
      high: allFindings.filter(f => f.severity === 'high').length,
      warning: allFindings.filter(f => f.severity === 'warning').length,
      quantumVulnerable: allFindings.filter(f => f.quantumVulnerable).length,
      uniqueAlgorithms: [...new Set(allFindings.map(f => f.algorithmId))],
      uniqueSafeAlgorithms: [...new Set(allSafe.map(f => f.id))],
    };

    return { findings: allFindings, safeFindings: allSafe, summary };
  }

  // ═══════════════════════════════════════════════════════
  // 2. TLS SCANNER — SSLyze-Powered Deep Analysis
  // ═══════════════════════════════════════════════════════

  /**
   * Run an SSLyze scan via the Python backend API.
   * @param {string} hostname - Target hostname
   * @param {number} port - Target port (default 443)
   * @returns {Promise<object>} Parsed SSLyze results
   */
  async function scanWithSSLyze(hostname, port = 443) {
    // Normalize hostname
    let host = hostname.trim();
    ['https://', 'http://'].forEach(prefix => {
      if (host.startsWith(prefix)) host = host.slice(prefix.length);
    });
    host = host.split('/')[0];

    const response = await fetch(`${SSLYZE_API_URL}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hostname: host, port }),
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.error || `API error: ${response.status}`);
    }

    return await response.json();
  }

  /**
   * Parse SSLyze results into a normalized structure for CBOM integration.
   * @param {object} sslyzeData - Raw SSLyze API response
   * @returns {object} Normalized TLS findings
   */
  function parseSSLyzeResults(sslyzeData) {
    const parsed = {
      hostname: sslyzeData.hostname,
      port: sslyzeData.port,
      timestamp: sslyzeData.timestamp,
      score: sslyzeData.quantum_score || 0,
      status: sslyzeData.status,
      connectivity: sslyzeData.connectivity,
      ip_address: sslyzeData.ip_address,
      scan_duration: sslyzeData.scan_duration,

      // Protocol support summary
      protocols: {},
      // All accepted cipher suites (flat list)
      cipherSuites: [],
      // Certificate details
      certificate: null,
      // Vulnerabilities
      vulnerabilities: sslyzeData.vulnerabilities || {},
      // Elliptic curves
      ellipticCurves: sslyzeData.elliptic_curves || {},
      // Mozilla compliance
      mozillaCompliance: sslyzeData.mozilla_compliance || null,
      // Quantum assessment breakdown
      quantumAssessment: sslyzeData.quantum_assessment || {},
      // Recommendations
      recommendations: sslyzeData.recommendations || [],
      // Errors
      errors: sslyzeData.errors || [],
    };

    // Flatten protocol support
    const protoSupport = sslyzeData.protocol_support || {};
    const protoNames = {
      ssl_2_0: 'SSL 2.0', ssl_3_0: 'SSL 3.0',
      tls_1_0: 'TLS 1.0', tls_1_1: 'TLS 1.1',
      tls_1_2: 'TLS 1.2', tls_1_3: 'TLS 1.3',
    };

    Object.entries(protoSupport).forEach(([key, data]) => {
      parsed.protocols[protoNames[key] || key] = {
        supported: data.supported,
        cipherCount: (data.cipher_suites || []).length,
        totalAttempted: data.total_attempted || 0,
      };

      // Collect cipher suites
      (data.cipher_suites || []).forEach(cs => {
        parsed.cipherSuites.push({
          name: cs.name,
          keySize: cs.key_size,
          protocol: protoNames[key] || key,
          keyExchange: cs.key_exchange || null,
          // Determine quantum vulnerability
          quantumVulnerable: _isCipherQuantumVulnerable(cs),
        });
      });
    });

    // Certificate
    const certs = sslyzeData.certificate_info || [];
    if (certs.length > 0) {
      const cert = certs[0];
      parsed.certificate = {
        subject: cert.subject,
        issuer: cert.issuer,
        keyType: cert.key_type,
        keySize: cert.key_size,
        signatureAlgorithm: cert.signature_algorithm,
        notBefore: cert.not_before,
        notAfter: cert.not_after,
        sanDnsNames: cert.san_dns_names || [],
        chain: cert.chain || [],
        trustStores: cert.trust_stores || {},
        ocspStapling: cert.ocsp_stapling,
        ocspMustStaple: cert.ocsp_must_staple,
        quantumVulnerable: /RSA|EC|DSA/.test(cert.key_type || ''),
      };
    }

    return parsed;
  }

  /**
   * Determine if a cipher suite uses quantum-vulnerable key exchange.
   */
  function _isCipherQuantumVulnerable(cs) {
    const name = (cs.name || '').toUpperCase();
    // TLS 1.3 ciphers don't embed key exchange — inherits from handshake
    if (name.startsWith('TLS_AES') || name.startsWith('TLS_CHACHA20')) {
      // TLS 1.3 — key exchange is separate, typically ECDHE (quantum-vulnerable)
      return true; // conservative: assume ECDHE unless ML-KEM detected
    }
    // Explicit quantum-vulnerable key exchange in cipher name
    if (/ECDHE|ECDH|RSA|DHE|DH/.test(name)) return true;
    // PQC key exchange
    if (/KYBER|ML.KEM/.test(name)) return false;
    return true; // default conservative
  }

  // ═══════════════════════════════════════════════════════
  // 3. CRYPTODEPS — Dependency Analysis
  // ═══════════════════════════════════════════════════════
  function scanDependencies(filename, content) {
    const results = { filename, format: 'unknown', dependencies: [], vulnerable: [], safe: [], summary: {} };

    let deps = {};
    const lowerName = filename.toLowerCase();

    try {
      if (lowerName.includes('package.json') || lowerName.endsWith('.json')) {
        const pkg = JSON.parse(content);
        deps = { ...pkg.dependencies, ...pkg.devDependencies };
        results.format = 'npm (package.json)';
      } else if (lowerName.includes('requirements') || lowerName.endsWith('.txt')) {
        content.split('\n').forEach(line => {
          const clean = line.trim().split('#')[0].trim();
          if (!clean) return;
          const parts = clean.split(/[=<>!~]+/);
          if (parts[0]) deps[parts[0].trim().toLowerCase()] = parts[1]?.trim() || '*';
        });
        results.format = 'pip (requirements.txt)';
      } else if (lowerName.endsWith('.toml') || lowerName.includes('cargo')) {
        const depSection = content.match(/\[dependencies\]([\s\S]*?)(?:\[|\s*$)/i);
        if (depSection) {
          depSection[1].split('\n').forEach(line => {
            const match = line.match(/^(\S+)\s*=\s*["']?([^"'\s]+)/);
            if (match) deps[match[1]] = match[2];
          });
        }
        results.format = 'cargo (Cargo.toml)';
      } else if (lowerName.includes('go.mod') || lowerName.endsWith('.mod')) {
        content.split('\n').forEach(line => {
          const match = line.match(/^\s*(\S+\/\S+)\s+(v[\d.]+)/);
          if (match) deps[match[1]] = match[2];
        });
        results.format = 'go (go.mod)';
      } else if (lowerName.includes('pom.xml') || lowerName.endsWith('.xml')) {
        const artMatches = content.matchAll(/<artifactId>([^<]+)<\/artifactId>/gi);
        for (const m of artMatches) deps[m[1]] = '*';
        results.format = 'maven (pom.xml)';
      } else if (lowerName.includes('gemfile') || lowerName.endsWith('.gemfile')) {
        content.split('\n').forEach(line => {
          const match = line.match(/^\s*gem\s+['"](\S+)['"]/);
          if (match) deps[match[1]] = '*';
        });
        results.format = 'ruby (Gemfile)';
      }
    } catch (e) {
      results.format = 'parse error: ' + e.message;
    }

    // Check each dependency against vulnerability database
    Object.keys(deps).forEach(dep => {
      const depLower = dep.toLowerCase();
      const version = deps[dep];
      results.dependencies.push({ name: dep, version });

      // Check direct match
      const vuln = VULN_DEPS[depLower] || VULN_DEPS[dep];
      if (vuln) {
        results.vulnerable.push({
          name: dep,
          version,
          algorithm: vuln.algo,
          severity: vuln.severity,
          alternative: vuln.alt,
          lang: vuln.lang
        });
      }

      // Check partial match for Go-style imports
      Object.keys(VULN_DEPS).forEach(vKey => {
        if (depLower.includes(vKey) && !results.vulnerable.find(v => v.name === dep)) {
          results.vulnerable.push({
            name: dep,
            version,
            algorithm: VULN_DEPS[vKey].algo,
            severity: VULN_DEPS[vKey].severity,
            alternative: VULN_DEPS[vKey].alt,
            lang: VULN_DEPS[vKey].lang
          });
        }
      });
    });

    results.summary = {
      totalDependencies: results.dependencies.length,
      vulnerableCount: results.vulnerable.length,
      critical: results.vulnerable.filter(v => v.severity === 'critical').length,
      high: results.vulnerable.filter(v => v.severity === 'high').length,
      warning: results.vulnerable.filter(v => v.severity === 'warning').length,
    };

    return results;
  }

  // ═══════════════════════════════════════════════════════
  // 4. CBOM GENERATOR — Cryptographic Bill of Materials
  // ═══════════════════════════════════════════════════════
  function generateCBOM(scanResults, tlsResults, depResults, orgName) {
    const cbom = {
      cbomVersion: '1.0',
      generatedAt: new Date().toISOString(),
      organization: orgName || 'Unknown Organization',
      generator: 'QuantumGuard Scanner v1.0',
      summary: {
        totalAssets: 0,
        quantumVulnerable: 0,
        quantumSafe: 0,
        pqcLabel: 'Not Assessed'
      },
      assets: []
    };

    // Add source code findings
    if (scanResults) {
      scanResults.findings.forEach(f => {
        cbom.assets.push({
          type: 'source-code',
          location: `${f.file}:${f.line}`,
          algorithm: f.algorithm,
          algorithmType: f.type,
          keySize: null,
          quantumSafe: false,
          severity: f.severity,
          recommendation: f.recommendation,
          pqcAlternative: f.pqcAlternative
        });
      });
      scanResults.safeFindings.forEach(f => {
        cbom.assets.push({
          type: 'source-code',
          location: `${f.file}:${f.line}`,
          algorithm: f.algorithm,
          algorithmType: f.type,
          keySize: null,
          quantumSafe: true,
          severity: 'safe',
          recommendation: 'PQC-compliant algorithm detected',
          pqcAlternative: 'N/A'
        });
      });
    }

    // Add TLS findings from SSLyze scan
    if (tlsResults && tlsResults.hostname) {
      // Add each cipher suite as a CBOM asset
      const cipherSuites = tlsResults.cipherSuites || [];
      if (cipherSuites.length > 0) {
        cipherSuites.forEach(cs => {
          cbom.assets.push({
            type: 'tls-cipher',
            location: `${tlsResults.hostname}:${tlsResults.port || 443} (${cs.protocol})`,
            algorithm: cs.name,
            algorithmType: 'cipher-suite',
            keySize: cs.keySize,
            quantumSafe: !cs.quantumVulnerable,
            severity: cs.quantumVulnerable ? 'warning' : 'safe',
            recommendation: cs.quantumVulnerable ? 'Migrate to PQC-hybrid cipher suite' : 'Quantum-safe cipher',
            pqcAlternative: cs.quantumVulnerable ? 'TLS 1.3 with ML-KEM hybrid key exchange' : 'N/A'
          });
        });
      }

      // Add certificate as CBOM asset
      if (tlsResults.certificate) {
        const cert = tlsResults.certificate;
        cbom.assets.push({
          type: 'tls-certificate',
          location: `${tlsResults.hostname}:${tlsResults.port || 443}`,
          algorithm: `${cert.keyType} (${cert.keySize || '?'}-bit)`,
          algorithmType: 'certificate',
          keySize: cert.keySize,
          quantumSafe: !cert.quantumVulnerable,
          severity: cert.quantumVulnerable ? 'critical' : 'safe',
          recommendation: cert.quantumVulnerable ? `${cert.keyType} certificate is quantum-vulnerable` : 'PQC certificate',
          pqcAlternative: cert.quantumVulnerable ? 'ML-DSA (FIPS 204) / SLH-DSA (FIPS 205)' : 'N/A'
        });
      }
    }

    // Add dependency findings
    if (depResults) {
      depResults.vulnerable.forEach(v => {
        cbom.assets.push({
          type: 'dependency',
          location: `${depResults.filename} → ${v.name}@${v.version}`,
          algorithm: v.algorithm,
          algorithmType: 'library',
          keySize: null,
          quantumSafe: false,
          severity: v.severity,
          recommendation: `Replace with: ${v.alternative}`,
          pqcAlternative: v.alternative
        });
      });
    }

    // Update summary
    cbom.summary.totalAssets = cbom.assets.length;
    cbom.summary.quantumVulnerable = cbom.assets.filter(a => !a.quantumSafe).length;
    cbom.summary.quantumSafe = cbom.assets.filter(a => a.quantumSafe).length;
    cbom.summary.pqcLabel = getPQCLabel(cbom);

    return cbom;
  }

  // ═══════════════════════════════════════════════════════
  // 5. PQC LABELER — Quantum-Safe Certification
  // ═══════════════════════════════════════════════════════
  function getPQCLabel(cbom) {
    if (!cbom || cbom.summary.totalAssets === 0) return 'Not Assessed';

    const vulnPct = cbom.summary.quantumVulnerable / cbom.summary.totalAssets;
    const safePct = cbom.summary.quantumSafe / cbom.summary.totalAssets;
    const hasCritical = cbom.assets.some(a => a.severity === 'critical' && !a.quantumSafe);

    if (vulnPct === 0 && safePct === 1) return 'Fully Quantum Safe';
    if (vulnPct === 0) return 'PQC Ready';
    if (vulnPct <= 0.2 && !hasCritical) return 'Partially Compliant';
    return 'Not Quantum Safe';
  }

  function getPQCLabelDetails(label) {
    const labels = {
      'Fully Quantum Safe': { color: '#10B981', icon: 'verified', bg: '#10B98120', desc: 'All cryptographic assets use NIST-standardized Post-Quantum algorithms. System is shielded against future cryptanalytic threats.' },
      'PQC Ready': { color: '#00D4FF', icon: 'shield_with_heart', bg: '#00D4FF20', desc: 'No quantum-vulnerable algorithms detected. System uses modern cryptographic primitives safe against known quantum attacks.' },
      'Partially Compliant': { color: '#F59E0B', icon: 'warning', bg: '#F59E0B20', desc: 'Some quantum-vulnerable algorithms remain. Migration to PQC alternatives is recommended within 12 months.' },
      'Not Quantum Safe': { color: '#F43F5E', icon: 'gpp_bad', bg: '#F43F5E20', desc: 'Critical quantum-vulnerable algorithms detected. Immediate assessment and migration planning required.' },
      'Not Assessed': { color: '#859398', icon: 'help', bg: '#85939820', desc: 'No scan has been performed yet. Run a scan to assess quantum readiness.' },
    };
    return labels[label] || labels['Not Assessed'];
  }

  // ═══════════════════════════════════════════════════════
  // PUBLIC API
  // ═══════════════════════════════════════════════════════
  return {
    // CryptoScan
    scanSource,
    scanMultipleFiles,
    VULN_PATTERNS,
    SAFE_PATTERNS,

    // TLS Scanner (SSLyze)
    scanWithSSLyze,
    parseSSLyzeResults,
    SSLYZE_API_URL,
    CNSA2_REQUIREMENTS,

    // CryptoDeps
    scanDependencies,
    VULN_DEPS,

    // CBOM & PQC Labels
    generateCBOM,
    getPQCLabel,
    getPQCLabelDetails,
  };
})();

// Export for Node.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = Scanner;
}
