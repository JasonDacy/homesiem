"""Small Flask dashboard: searchable event log, alerts, and severity chart.

Binds to localhost by default so the dashboard is not exposed to the
network. Read-only views over the SQLite storage.
"""
from __future__ import annotations

from flask import Flask, jsonify, render_template, request

from ..storage import Storage


def create_app(storage: Storage) -> Flask:
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/events")
    def api_events():
        category = request.args.get("category") or None
        limit = min(int(request.args.get("limit", 200)), 1000)
        return jsonify(storage.recent_events(limit=limit, category=category))

    @app.route("/api/alerts")
    def api_alerts():
        return jsonify(storage.recent_alerts(limit=100))

    @app.route("/api/stats")
    def api_stats():
        return jsonify({"severity_counts": storage.severity_counts()})

    return app
