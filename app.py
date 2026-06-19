"""
app.py — Flask Web Dashboard Server (PDF Report Enabled)
"""

import os
import tempfile
from datetime import datetime
from io import BytesIO
from flask import Flask, render_template, jsonify, request, send_file

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
ALLOWED_PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


# ─── Helpers ──────────────────────────────────────────────────────────────

def _allowed_pcap(filename: str) -> bool:
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_PCAP_EXTENSIONS


def _run_pipeline(incident: dict) -> dict:
    from dnn_model import predict_from_incident
    from analyzer import analyze_incident
    from alert_system import check_and_send_alert
    from responder import save_incident

    dnn_result = predict_from_incident(incident)
    incident["dnn"] = dnn_result
    print(f"[Pipeline] 🧠 DNN: {dnn_result['label']} (score={dnn_result['threat_score']})")

    analysis = analyze_incident(incident, dnn_result)
    incident["analysis"] = analysis

    alert = check_and_send_alert(incident, analysis)
    incident["alert"] = alert

    return save_incident(incident)


# ─── Routes ──────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/incidents")
def api_incidents():
    from responder import get_all_incidents
    incidents = get_all_incidents()
    severity = request.args.get("severity", "").upper()
    if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        incidents = [i for i in incidents if i.get("severity") == severity]
    try:
        limit = int(request.args.get("limit", 0))
        if limit > 0:
            incidents = incidents[:limit]
    except ValueError:
        pass
    return jsonify(incidents)


@app.route("/api/incidents/<incident_id>")
def api_incident_by_id(incident_id: str):
    from responder import get_all_incidents
    for incident in get_all_incidents():
        if str(incident.get("id")) == incident_id:
            return jsonify(incident)
    return jsonify({"status": "error", "message": f"Incident '{incident_id}' not found"}), 404


@app.route("/api/incidents", methods=["DELETE"])
def api_clear_incidents():
    try:
        from responder import clear_log
        clear_log()
        return jsonify({"status": "success", "message": "All incidents cleared"})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@app.route("/api/stats")
def api_stats():
    from responder import get_stats
    return jsonify(get_stats())


@app.route("/api/scan", methods=["POST"])
def api_scan():
    try:
        from detector import detect_simulated_incident
        incident = detect_simulated_incident()
        print(f"\n[Scan] 🔍 Detected: {incident['type']} ({incident['severity']})")
        saved = _run_pipeline(incident)
        return jsonify({"status": "success", "incident": saved})
    except Exception as exc:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(exc)}), 500


@app.route("/api/upload/pcap", methods=["POST"])
def api_upload_pcap():
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file part"}), 400
    upload = request.files["file"]
    if not upload.filename:
        return jsonify({"status": "error", "message": "No file selected"}), 400
    if not _allowed_pcap(upload.filename):
        return jsonify({
            "status": "error",
            "message": f"Invalid file type. Accepted: {', '.join(sorted(ALLOWED_PCAP_EXTENSIONS))}"
        }), 415

    suffix = os.path.splitext(upload.filename)[1].lower()
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            upload.save(tmp.name)
            tmp_path = tmp.name
        print(f"\n[PCAP] 📂 Received '{upload.filename}'")
        from pcap_reader import read_pcap_incidents
        raw_incidents = read_pcap_incidents(tmp_path)
        print(f"[PCAP] 📦 Extracted {len(raw_incidents)} incident(s)")
        processed = []
        for incident in raw_incidents:
            print(f"[PCAP] 🔍 Processing: {incident['type']} ({incident['severity']})")
            saved = _run_pipeline(incident)
            processed.append(saved)
        return jsonify({
            "status": "success",
            "source": upload.filename,
            "count": len(processed),
            "incidents": processed,
        })
    except Exception as exc:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(exc)}), 500
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


@app.route("/api/report", methods=["GET"])
def api_report():
    """Generate and download the forensic report as PDF (or HTML fallback)."""
    try:
        from responder import get_all_incidents, get_stats
        from report_generator import generate_pdf_bytes

        incidents = get_all_incidents()
        stats = get_stats()

        pdf_bytes = generate_pdf_bytes(incidents, stats)
        pdf_io = BytesIO(pdf_bytes)
        pdf_io.seek(0)

        fname = f"forensic_report_{datetime.now().strftime('%Y-%m-%d')}.pdf"
        return send_file(
            pdf_io,
            as_attachment=True,
            download_name=fname,
            mimetype="application/pdf",
        )
    except Exception as e:
        # Fallback to HTML if PDF generation fails (e.g., wkhtmltopdf not installed)
        print(f"[Report] ⚠️ PDF generation failed: {e}. Falling back to HTML.")
        try:
            from responder import get_all_incidents, get_stats
            from report_generator import generate_report
            incidents = get_all_incidents()
            stats = get_stats()
            report_path = generate_report(incidents, stats, fmt="html")
            fname = f"forensic_report_{datetime.now().strftime('%Y-%m-%d')}.html"
            return send_file(
                report_path,
                as_attachment=True,
                download_name=fname,
                mimetype="text/html",
            )
        except Exception as exc2:
            return jsonify({"status": "error", "message": str(exc2)}), 500


@app.route("/api/status")
def api_status():
    try:
        import pcap_reader
        pcap_available = True
    except ImportError:
        pcap_available = False
    return jsonify({
        "version": "2.0",
        "model_loaded": True,
        "groq_configured": bool(os.getenv("GROQ_API_KEY")),
        "email_configured": bool(os.getenv("SMTP_EMAIL") and os.getenv("SMTP_PASSWORD")),
        "alert_threshold": os.getenv("ALERT_THRESHOLD", "high").upper(),
        "pcap_support": pcap_available,
        "timestamp": datetime.now().isoformat(),
    })


@app.route("/api/test-email", methods=["GET"])
def test_email_endpoint():
    from alert_system import test_email
    result = test_email()
    return jsonify(result)


# ─── Error Handlers ──────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(exc):
    return jsonify({"status": "error", "message": "Endpoint not found"}), 404


@app.errorhandler(405)
def method_not_allowed(exc):
    return jsonify({"status": "error", "message": "Method not allowed"}), 405


@app.errorhandler(413)
def payload_too_large(exc):
    return jsonify({
        "status": "error",
        "message": "Upload too large. Maximum 50 MB.",
    }), 413


# ─── Entry Point ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    print("\n" + "═" * 58)
    print("  🛡️  Incident Response Automation System v2.0")
    print("  🌐  Dashboard      → http://127.0.0.1:" + str(port))
    print("  🔍  POST /api/scan              → simulate an incident")
    print("  📂  POST /api/upload/pcap       → analyse a real capture")
    print("  📊  GET  /api/report            → download PDF report")
    print("  🗑️   DELETE /api/incidents       → clear all incidents")
    print("  📧  GET  /api/test-email        → test email configuration")
    print("═" * 58 + "\n")
    app.run(debug=True, port=port, use_reloader=False)