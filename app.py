"""
app.py
------
Flask application that exposes the NIDS dashboard and a small JSON API
on top of the IDSEngine (ids_core.py) and DBHandler (db_handler.py).

Run:
    sudo python app.py        # packet capture needs elevated privileges

Then open:
    http://127.0.0.1:5000

Author : Rithika U
Project: NIDS - Network Intrusion Detection System
"""

from flask import Flask, jsonify, render_template, request

from ids_core import IDSEngine

app = Flask(__name__)

# Single shared engine instance for the whole app.
# Pass interface="eth0" / "Wi-Fi" etc. to target a specific NIC.
ids_engine = IDSEngine(interface="lo", db_path="alerts.db")


# ----------------------------------------------------------------------
# Dashboard
# ----------------------------------------------------------------------
@app.route("/")
def dashboard():
    return render_template("dashboard.html")


# ----------------------------------------------------------------------
# Engine control
# ----------------------------------------------------------------------
@app.route("/api/status")
def api_status():
    return jsonify({
        "running": ids_engine.running,
        "stats": ids_engine.get_stats(),
    })


@app.route("/api/start", methods=["POST"])
def api_start():
    started = ids_engine.start()
    return jsonify({"success": started, "running": ids_engine.running})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    ids_engine.stop()
    return jsonify({"success": True, "running": ids_engine.running})


# ----------------------------------------------------------------------
# Alerts
# ----------------------------------------------------------------------
@app.route("/api/alerts")
def api_alerts():
    limit = request.args.get("limit", default=100, type=int)
    severity = request.args.get("severity", default=None, type=str)
    return jsonify(ids_engine.db.get_alerts(limit=limit, severity=severity))


@app.route("/api/alerts/clear", methods=["POST"])
def api_alerts_clear():
    ids_engine.db.clear_alerts()
    return jsonify({"success": True})


@app.route("/api/summary")
def api_summary():
    return jsonify(ids_engine.db.get_alert_counts())


# ----------------------------------------------------------------------
if __name__ == "__main__":
    # debug=False recommended once packet sniffing is active, since the
    # Flask reloader spawns a second process.
    app.run(host="0.0.0.0", port=5000, debug=False)
