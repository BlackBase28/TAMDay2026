from __future__ import annotations

import random

from flask import Blueprint, abort, redirect, render_template, request, url_for

from .db import query_all, query_one
from .logging_utils import log_activity

bp = Blueprint("public", __name__)


@bp.get("/")
def index():
    severity = request.args.get("severity", "").strip()
    subsystem = request.args.get("subsystem", "").strip()
    version = request.args.get("version", "").strip()

    clauses = ["enabled = 1"]
    params: list[str] = []
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    if subsystem:
        clauses.append("subsystem = ?")
        params.append(subsystem)
    if version:
        clauses.append("affected_versions LIKE ?")
        params.append(f"%{version}%")

    cves = query_all(
        f"SELECT * FROM cves WHERE {' AND '.join(clauses)} ORDER BY published_date DESC, id DESC",
        params,
    )
    filters = {
        "severities": query_all("SELECT DISTINCT severity FROM cves WHERE enabled=1 ORDER BY severity"),
        "subsystems": query_all("SELECT DISTINCT subsystem FROM cves WHERE enabled=1 ORDER BY subsystem"),
    }
    stats = query_one(
        """
        SELECT COUNT(*) AS total,
               SUM(CASE WHEN status='Ongoing' THEN 1 ELSE 0 END) AS ongoing,
               SUM(CASE WHEN reboot_required=1 THEN 1 ELSE 0 END) AS reboot
        FROM cves WHERE enabled=1
        """
    )
    log_activity("view_home", request.args.to_dict(), f"{len(cves)} cves")
    return render_template("index.html", cves=cves, filters=filters, stats=stats)


@bp.get("/cve/<int:cve_pk>")
def cve_detail(cve_pk: int):
    cve = query_one("SELECT * FROM cves WHERE id=? AND enabled=1", (cve_pk,))
    if not cve:
        abort(404)
    log_activity("view_cve", {"cve": cve["cve_id"]}, "viewed")
    return render_template("cve_detail.html", cve=cve)


@bp.route("/challenge", methods=["GET", "POST"])
def challenge():
    if request.method == "POST":
        scenario_id = request.form.get("scenario_id", type=int)
        option_id = request.form.get("option_id", type=int)
        scenario = query_one("SELECT * FROM scenarios WHERE id=? AND enabled=1", (scenario_id,))
        selected = query_one(
            """
            SELECT so.*, c.cve_id, c.name
            FROM scenario_options so JOIN cves c ON c.id=so.cve_id
            WHERE so.id=? AND so.scenario_id=?
            """,
            (option_id, scenario_id),
        )
        if not scenario or not selected:
            abort(400, "題目或選項不存在")
        correct = bool(selected["is_correct"])
        log_activity(
            "submit_challenge",
            {"scenario_id": scenario_id, "selected": selected["cve_id"], "label": selected["label"]},
            "correct" if correct else "incorrect",
        )
        return render_template(
            "challenge_result.html", scenario=scenario, selected=selected, correct=correct
        )

    requested_id = request.args.get("id", type=int)
    if requested_id:
        scenario = query_one("SELECT * FROM scenarios WHERE id=? AND enabled=1", (requested_id,))
    else:
        rows = query_all("SELECT * FROM scenarios WHERE enabled=1")
        scenario = random.choice(rows) if rows else None
    if not scenario:
        abort(404)
    options = query_all(
        """
        SELECT so.*, c.cve_id, c.name
        FROM scenario_options so JOIN cves c ON c.id=so.cve_id
        WHERE so.scenario_id=? ORDER BY so.sort_order, so.id
        """,
        (scenario["id"],),
    )
    log_activity("view_challenge", {"scenario_id": scenario["id"]}, "viewed")
    return render_template("challenge.html", scenario=scenario, options=options)


@bp.get("/healthz")
def healthz():
    return {"status": "ok"}


@bp.get("/random-cve")
def random_cve():
    rows = query_all("SELECT id FROM cves WHERE enabled=1")
    if not rows:
        abort(404)
    return redirect(url_for("public.cve_detail", cve_pk=random.choice(rows)["id"]))
