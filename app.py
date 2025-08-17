import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash
from scanners.nmap_scanner import run_nmap_scan
from scanners.port_scanner import run_port_scan
from scanners.web_scanner import run_basic_web_scan
from scanners.zap_scanner import run_zap_scan, is_zap_available
from scanners.cloud_scanner import run_cloud_scan

load_dotenv()  # Load variables from .env

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"]) 
def scan():
    target = request.form.get("target", "").strip()
    do_nmap = request.form.get("scan_nmap") == "on"
    do_ports = request.form.get("scan_ports") == "on"
    do_web = request.form.get("scan_web") == "on"
    do_zap = request.form.get("scan_zap") == "on"
    do_cloud = request.form.get("scan_cloud") == "on"

    if not target:
        flash("Please provide a target (IP/hostname or URL).", "warning")
        return redirect(url_for("index"))

    results = {"target": target, "scans": []}

    # Nmap
    if do_nmap:
        try:
            nmap_res = run_nmap_scan(target)
            results["scans"].append({"name": "Nmap", "data": nmap_res, "success": True})
        except Exception as e:
            msg = str(e)
            if "nmap is not installed" in msg.lower():
                results["scans"].append({
                    "name": "Nmap",
                    "data": {"skipped": True, "reason": "Nmap not installed; skipped. Use TCP Port Scan instead."},
                    "success": True,
                })
            else:
                results["scans"].append({"name": "Nmap", "error": msg, "success": False})

    # Port scanner
    if do_ports:
        try:
            ports_res = run_port_scan(target)
            results["scans"].append({"name": "TCP Port Scan", "data": ports_res, "success": True})
        except Exception as e:
            results["scans"].append({"name": "TCP Port Scan", "error": str(e), "success": False})

    # Basic web scan
    if do_web:
        try:
            web_res = run_basic_web_scan(target)
            results["scans"].append({"name": "Basic Web Scan", "data": web_res, "success": True})
        except Exception as e:
            results["scans"].append({"name": "Basic Web Scan", "error": str(e), "success": False})

    # ZAP scan
    if do_zap:
        if not is_zap_available():
            results["scans"].append({
                "name": "OWASP ZAP",
                "data": {"skipped": True, "reason": "ZAP daemon not running; scan skipped. Set ZAP_API_KEY and start ZAP."},
                "success": True,
            })
        else:
            try:
                zap_res = run_zap_scan(target)
                results["scans"].append({"name": "OWASP ZAP", "data": zap_res, "success": True})
            except Exception as e:
                results["scans"].append({"name": "OWASP ZAP", "error": str(e), "success": False})

    # Cloud Mode (Mozilla Observatory, SSL Labs, crt.sh)
    if do_cloud:
        try:
            cloud_res = run_cloud_scan(target)
            results["scans"].append({"name": "Cloud Scan", "data": cloud_res, "success": True})
        except Exception as e:
            results["scans"].append({"name": "Cloud Scan", "error": str(e), "success": False})

    return render_template("results.html", results=results)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
