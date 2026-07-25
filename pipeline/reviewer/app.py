"""Local-only Flask interface for blinded Echelon dataset review."""

from __future__ import annotations

import argparse
import hmac
import os
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from reviewer.distributed import load_json
from reviewer.store import decision_report, initialize_database, next_item, queue_sha256, save_review


def create_app(
    db_path: Path, review_token: str, expert_token: str,
    assigned_reviewer_id: str | None = None, assigned_role: str | None = None,
    expose_local_token: bool = False,
) -> Flask:
    app = Flask(__name__)
    app.config.update(
        DB_PATH=db_path, REVIEW_TOKEN=review_token, EXPERT_TOKEN=expert_token,
        ASSIGNED_REVIEWER_ID=assigned_reviewer_id, ASSIGNED_ROLE=assigned_role,
        EXPOSE_LOCAL_TOKEN=expose_local_token,
    )

    def assignment_matches(reviewer_id: str, expert: bool) -> bool:
        assigned_id = app.config["ASSIGNED_REVIEWER_ID"]
        assigned_role = app.config["ASSIGNED_ROLE"]
        return (
            (not assigned_id or reviewer_id == assigned_id)
            and (not assigned_role or ("expert" if expert else "primary") == assigned_role)
        )

    def authorized(expert: bool = False) -> bool:
        expected = app.config["EXPERT_TOKEN" if expert else "REVIEW_TOKEN"]
        supplied = request.headers.get("X-Review-Token", "")
        return bool(expected) and hmac.compare_digest(supplied, expected)

    @app.after_request
    def security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/next")
    def api_next():
        expert = request.args.get("role") == "expert"
        if not authorized(expert):
            return jsonify(error="unauthorized"), 401
        reviewer_id = request.args.get("reviewer_id", "").strip()
        if not assignment_matches(reviewer_id, expert):
            return jsonify(error="reviewer identity or role does not match this kit"), 403
        try:
            return jsonify(next_item(app.config["DB_PATH"], reviewer_id, expert))
        except ValueError as exc:
            return jsonify(error=str(exc)), 400

    @app.post("/api/reviews")
    def api_review():
        payload = request.get_json(silent=True) or {}
        expert = bool(payload.get("is_expert_adjudication"))
        if not authorized(expert):
            return jsonify(error="unauthorized"), 401
        if not assignment_matches(str(payload.get("reviewer_id", "")), expert):
            return jsonify(error="reviewer identity or role does not match this kit"), 403
        try:
            save_review(app.config["DB_PATH"], payload)
        except (KeyError, TypeError, ValueError) as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(saved=True), 201

    @app.get("/api/progress")
    def api_progress():
        if not authorized(False) and not authorized(True):
            return jsonify(error="unauthorized"), 401
        return jsonify(decision_report(app.config["DB_PATH"]))

    @app.get("/api/config")
    def api_config():
        return jsonify(
            assigned_reviewer_id=app.config["ASSIGNED_REVIEWER_ID"],
            assigned_role=app.config["ASSIGNED_ROLE"],
            local_token=app.config["REVIEW_TOKEN"] if app.config["EXPOSE_LOCAL_TOKEN"] else None,
        )

    return app


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--port", type=int, default=5080)
    parser.add_argument("--kit-manifest", type=Path)
    args = parser.parse_args()
    review_token = os.environ.get("ECHELON_REVIEW_TOKEN", "")
    expert_token = os.environ.get("ECHELON_EXPERT_TOKEN", "")
    assigned_id = assigned_role = None
    if args.kit_manifest:
        kit = load_json(args.kit_manifest)
        assigned_id, assigned_role = kit.get("assigned_reviewer_id"), kit.get("role")
        if queue_sha256(args.queue) != kit.get("review_queue_sha256"):
            parser.error("queue SHA-256 does not match kit manifest")
        if assigned_role not in {"primary", "expert"} or not assigned_id:
            parser.error("kit manifest has invalid assignment")
        if len(review_token) < 16:
            parser.error("set ECHELON_REVIEW_TOKEN to a local secret of at least 16 characters")
        expert_token = review_token
    elif len(review_token) < 16 or len(expert_token) < 16 or review_token == expert_token:
        parser.error("set distinct ECHELON_REVIEW_TOKEN and ECHELON_EXPERT_TOKEN values (16+ characters)")
    initialize_database(args.database, args.queue)
    app = create_app(args.database, review_token, expert_token, assigned_id, assigned_role)
    app.run(host="127.0.0.1", port=args.port, debug=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
