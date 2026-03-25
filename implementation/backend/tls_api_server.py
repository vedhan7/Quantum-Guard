"""
QuantumGuard TLS API Server
Flask API exposing SSLyze scanning via HTTP endpoints.
Production-ready: CORS whitelist, env-based config, Gunicorn-compatible.
"""

import os
import json
import queue
import threading
from flask import Flask, request, jsonify, Response, stream_with_context
from flask_cors import CORS

from sslyze_scanner import scan_host, scan_multiple_hosts
from subdomain_discovery import discover_subdomains
from chat_advisor import build_llm_payload, call_gemini_stream

app = Flask(__name__)

# ---------------------------------------------------------------------------
# CORS Configuration
# In production, restrict to your Vercel frontend domain.
# Set ALLOWED_ORIGINS env var as a comma-separated list, or use the default.
# ---------------------------------------------------------------------------
ALLOWED_ORIGINS = os.environ.get(
    'ALLOWED_ORIGINS',
    'https://quantum-guard-8bey.vercel.app,http://localhost:3000,http://localhost:5173'
).split(',')

CORS(app, origins=ALLOWED_ORIGINS)


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': 'QuantumGuard TLS Scanner API'})


@app.route('/scan', methods=['POST'])
def scan():
    """Run an SSLyze scan against a hostname."""
    data = request.get_json()
    if not data or 'hostname' not in data:
        return jsonify({'error': 'Missing required field: hostname'}), 400

    hostname = data['hostname'].strip()
    port = int(data.get('port', 443))

    if not hostname:
        return jsonify({'error': 'Hostname cannot be empty'}), 400

    # Strip protocol prefixes if provided
    for prefix in ['https://', 'http://']:
        if hostname.startswith(prefix):
            hostname = hostname[len(prefix):]
    # Strip trailing slashes and paths
    hostname = hostname.split('/')[0]
    # Strip port if provided in hostname
    if ':' in hostname:
        parts = hostname.split(':')
        hostname = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            pass

    try:
        result = scan_host(hostname, port)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'error': f'Scan failed: {str(e)}',
            'hostname': hostname,
            'port': port,
            'status': 'error',
        }), 500


@app.route('/scan/domain', methods=['POST'])
def scan_domain():
    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({'error': 'Missing required field: domain'}), 400

    domain = data['domain'].strip()
    port = int(data.get('port', 443))
    include_subdomains = data.get('include_subdomains', False)

    # Strip prefixes
    for prefix in ['https://', 'http://']:
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split('/')[0]
    if ':' in domain:
        domain = domain.split(':')[0]

    def generate():
        import time
        from datetime import datetime
        import uuid

        report_id = str(uuid.uuid4())
        start_time = time.time()

        active_targets = [{'hostname': domain, 'port': port}]
        all_subdomains_info = []

        if include_subdomains:
            discovery_res = discover_subdomains(domain)
            yield f"event: discovery\ndata: {json.dumps(discovery_res)}\n\n"

            all_subdomains_info = discovery_res.get('subdomains', [])
            for sub in all_subdomains_info:
                if sub['active'] and sub['name'] != domain:
                    active_targets.append({'hostname': sub['name'], 'port': port})
        else:
            yield f"event: discovery\ndata: {json.dumps({'subdomains': [], 'total_found': 0, 'active_count': 0})}\n\n"

        unique_targets = []
        seen = set()
        for t in active_targets:
            if t['hostname'] not in seen:
                seen.add(t['hostname'])
                unique_targets.append(t)

        total_hosts = len(unique_targets)
        q = queue.Queue()

        def progress_callback(hostname, result):
            q.put((hostname, result))

        def run_scans():
            scan_multiple_hosts(unique_targets, timeout=30, on_progress=progress_callback)
            q.put(None)

        scan_thread = threading.Thread(target=run_scans)
        scan_thread.start()

        completed_hosts = 0
        all_results = []
        main_domain_result = None
        subdomain_results = []

        while True:
            item = q.get()
            if item is None:
                break
            hostname_item, res = item
            completed_hosts += 1
            all_results.append(res)

            if hostname_item == domain:
                main_domain_result = res
            else:
                subdomain_results.append(res)

            progress_data = {
                'phase': 'scanning',
                'hostname': hostname_item,
                'result_summary': {
                    'status': res.get('status'),
                    'quantum_score': res.get('quantum_score', 0)
                },
                'completed': completed_hosts,
                'total': total_hosts
            }
            yield f"event: scan_progress\ndata: {json.dumps(progress_data)}\n\n"

        scan_thread.join()

        scan_duration = time.time() - start_time
        scanned_hostnames = {r['hostname'] for r in subdomain_results}

        for sub in all_subdomains_info:
            if sub['name'] != domain and sub['name'] not in scanned_hostnames:
                subdomain_results.append({
                    'hostname': sub['name'],
                    'status': 'unreachable' if not sub['active'] else 'error',
                    'errors': ['Host not active/unreachable during discovery'],
                    'quantum_score': 0,
                    'quantum_assessment': {}
                })

        valid_scores = [r.get('quantum_score', 0) for r in all_results if r.get('status') == 'completed']
        avg_score = sum(valid_scores) / len(valid_scores) if valid_scores else 0

        critical_vulns = 0
        tls_1_3_hosts = 0
        for r in all_results:
            if r.get('status') == 'completed':
                if 'TLS 1.3' in r.get('supported_tls_versions', []):
                    tls_1_3_hosts += 1
                assessment = r.get('quantum_assessment', {})
                if assessment.get('risk_level') == 'CRITICAL':
                    critical_vulns += 1

        pq_ready = any(r.get('quantum_assessment', {}).get('post_quantum_ready', False) for r in all_results if r.get('status') == 'completed')

        unified_report = {
            'report_id': report_id,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'domain': domain,
            'scan_duration_total': round(scan_duration, 2),
            'summary': {
                'total_hosts_scanned': total_hosts,
                'active_hosts': len([r for r in all_results if r.get('status') == 'completed']),
                'unreachable_hosts': total_hosts - len(valid_scores),
                'average_quantum_score': round(avg_score, 1),
                'post_quantum_ready': pq_ready,
                'critical_vulnerabilities': critical_vulns,
                'hosts_with_tls_1_3': tls_1_3_hosts
            },
            'main_domain': main_domain_result or {
                'hostname': domain,
                'status': 'error',
                'errors': ['Scan not completed for main domain']
            },
            'subdomains': subdomain_results
        }

        yield f"event: scan_complete\ndata: {json.dumps(unified_report)}\n\n"

    return Response(stream_with_context(generate()), content_type='text/event-stream')


@app.route('/chat/advisor', methods=['POST'])
def chat_advisor():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No JSON payload provided"}), 400

        user_message = data.get('message', '')
        report_context = data.get('report_context', {})
        history = data.get('history', [])[-10:]

        if not user_message:
            return jsonify({"error": "Message cannot be empty"}), 400

        print(f"[ChatAdvisor] Request: '{user_message[:80]}...' | Context keys: {list(report_context.keys()) if isinstance(report_context, dict) else 'N/A'}")

        payload = build_llm_payload(report_context, history, user_message)

        def generate():
            has_yielded = False
            try:
                for text_chunk in call_gemini_stream(payload):
                    has_yielded = True
                    chunk_data = json.dumps({"text": text_chunk})
                    yield f"data: {chunk_data}\n\n"
                if not has_yielded:
                    yield f"data: {json.dumps({'text': 'No response received from AI. Please try again.'})}\n\n"
            except Exception as e:
                print(f"[ChatAdvisor] Stream error: {e}")
                yield f"data: {json.dumps({'text': f'Stream error: {str(e)}'})}\n\n"
            yield "data: [DONE]\n\n"

        return Response(stream_with_context(generate()), content_type='text/event-stream')
    except Exception as e:
        print(f"[ChatAdvisor] FATAL: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_DEBUG', 'true').lower() == 'true'
    print("=" * 60)
    print("  QuantumGuard TLS Scanner API")
    print(f"  Starting on http://localhost:{port}")
    print(f"  CORS origins: {ALLOWED_ORIGINS}")
    print("=" * 60)
    app.run(host='0.0.0.0', port=port, debug=debug)
