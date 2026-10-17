"""Report generation: account register, audit report, offboarding report, run log.

Every report states its data classification (synthetic demo vs company test
environment) and the real state of each integration, so synthetic or
human-confirmed results are never presented as live machine verification.
Every written file is passed through the redactor and then scanned for any
registered secret before it is kept; a hit deletes the file and raises.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.clock import Clock
from app.config import ENVIRONMENT_LABELS, Settings
from app.enums import FindingStatus, OffboardingActionStatus, OffboardingActionType
from app.integrations.meta.base import MetaIntegration
from app.integrations.notifications.base import Notifier
from app.integrations.vault.base import VaultAdapter
from app.logging_setup import RUN_LOG_FILENAME, log_event
from app.models import AuditFinding, AuditRun, InstagramAccount, OffboardingCase
from app.security.redaction import Redactor
from app.services.provisioning import ProvisioningService
from app.views import account_view, case_view, finding_view, iso

logger = logging.getLogger("app.reports")

LABEL_LEGEND = {
    "integration_verified": "Read directly from the authoritative system (configured integration, or this application's own records where it is the system of record).",
    "human_confirmed": "Attested by a named, authorised human with an evidence reference; not machine-verified.",
    "unverified": "No adequate evidence either way. Missing evidence is not proof of failure.",
}


class SecretLeakDetected(RuntimeError):
    pass


def _md_escape(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return "_None._\n"
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(_md_escape(c) for c in row) + " |" for row in rows]
    return "\n".join(out) + "\n"


class ReportService:
    def __init__(
        self,
        *,
        settings: Settings,
        clock: Clock,
        redactor: Redactor,
        vault: VaultAdapter,
        meta: MetaIntegration,
        notifier: Notifier,
        provisioning: ProvisioningService,
    ):
        self.settings = settings
        self.clock = clock
        self.redactor = redactor
        self.vault = vault
        self.meta = meta
        self.notifier = notifier
        self.provisioning = provisioning

    # ------------------------------------------------------------------ common
    def report_meta(self, session: Session, title: str) -> dict[str, Any]:
        flags = list(session.scalars(select(InstagramAccount.is_synthetic)))
        live_label = self.settings.environment_label.upper()
        if not flags:
            classification = "NO_ACCOUNTS"
        elif all(flags):
            classification = "SYNTHETIC_DEMO_DATA"
        elif not any(flags):
            classification = live_label
        else:
            classification = f"MIXED_SYNTHETIC_AND_{live_label}"
        notes = []
        if classification.startswith("SYNTHETIC") or classification.startswith("MIXED"):
            notes.append(
                "Contains explicitly synthetic records created by scripts/seed_demo.py. Synthetic results are NOT "
                "live-account verification."
            )
        if flags and not all(flags):
            notes.append(ENVIRONMENT_LABELS[self.settings.environment_label])
        if self.vault.name == "dev_memory":
            notes.append("Vault: development-only in-memory vault holding synthetic secrets - not the company vault.")
        elif self.vault.name == "reference_only":
            notes.append("Vault: reference-only mode - vault presence is human-confirmed, not machine-verified.")
        elif self.vault.name == "hashicorp_kv2":
            who = (
                "a candidate-run HashiCorp Vault (not the company vault)"
                if self.settings.environment_label == "candidate_provided_test_environment"
                else "HashiCorp Vault"
            )
            notes.append(
                f"Vault: {who}, KV v2. Presence and versions of vault:// references are machine-verified; the application "
                "token may not read Instagram secret values. References to other password managers stay human-confirmed."
            )
        if not self.meta.configured:
            notes.append("Meta: integration not configured - business association is human-confirmed.")
        if not self.notifier.configured:
            notes.append("Notifications: no provider configured - reminders/escalations were queued and shown on the dashboard but NOT delivered.")
        return {
            "title": title,
            "generated_at": iso(self.clock.now()),
            "generator": self.settings.app_name,
            "data_classification": classification,
            "integrations": {
                "vault": {"backend": self.vault.name, "production_grade": self.vault.production_grade},
                "meta": {"mode": self.meta.name, "configured": self.meta.configured},
                "notifications": {"backend": self.notifier.name, "configured": self.notifier.configured},
            },
            "verification_labels": LABEL_LEGEND,
            "notes": notes,
        }

    def _write(self, path: Path, text: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        safe = self.redactor.redact_text(text) if path.suffix in (".md", ".csv") else text
        path.write_text(safe, encoding="utf-8")
        self.assert_no_secrets(path)
        return path

    def _write_json(self, path: Path, data: dict[str, Any]) -> Path:
        return self._write(path, json.dumps(self.redactor.redact(data), indent=2, ensure_ascii=False, default=str))

    def write_json_report(self, path: Path, data: dict[str, Any]) -> Path:
        """Write any JSON report through the same redaction and leak guard."""
        return self._write_json(path, data)

    def assert_no_secrets(self, path: Path) -> None:
        if self.redactor.contains_registered_secret(path.read_text(encoding="utf-8")):
            path.unlink(missing_ok=True)
            raise SecretLeakDetected(f"a registered secret was found in {path.name}; the file was deleted")

    def _stamp(self) -> str:
        return self.clock.now().strftime("%Y%m%dT%H%M%SZ")

    # ------------------------------------------------------------------ account register
    def account_register(self, session: Session) -> dict[str, Any]:
        now = self.clock.now()
        accounts = session.scalars(select(InstagramAccount).order_by(InstagramAccount.created_at)).all()
        return {
            "report_meta": self.report_meta(session, "Account register"),
            "accounts": [account_view(session, a, now, self.provisioning.provisioning_gaps(a)) for a in accounts],
        }

    def account_register_markdown(self, data: dict[str, Any]) -> str:
        meta = data["report_meta"]
        lines = [
            "# Account register",
            "",
            f"Generated: {meta['generated_at']}  ",
            f"Data classification: **{meta['data_classification']}**",
            "",
            *[f"> {note}" for note in meta["notes"]],
            "",
        ]
        for a in data["accounts"]:
            lines += [
                f"## {a['brand_name']} (@{a['handles']['selected'] or 'handle not selected'}) - {a['provisioning_status']}",
                "",
                _table(
                    ["Field", "Value", "Verification"],
                    [
                        ["Account ID", a["id"], ""],
                        ["Synthetic record", a["is_synthetic"], ""],
                        ["Owner", (a["owner"] or {}).get("name"), ""],
                        ["Company email", f"{a['company_contacts']['email_assignment_ref']} ({a['company_contacts']['email_hint']}) - {a['company_contacts']['email_control']}", ""],
                        ["Company phone", f"{a['company_contacts']['phone_assignment_ref']} ({a['company_contacts']['phone_hint']}) - {a['company_contacts']['phone_control']}", ""],
                        ["Recovery email", a["recovery"]["email_control"], a["recovery"]["email_verification"]],
                        ["Recovery phone", a["recovery"]["phone_control"], a["recovery"]["phone_verification"]],
                        ["Two-factor", f"{a['two_factor']['status']} via {a['two_factor']['method']}", a["two_factor"]["verification"]],
                        ["Backup codes", f"{a['backup_codes']['status']} @ {a['backup_codes']['vault_ref']}", a["backup_codes"]["verification"]],
                        ["Password", a["vault_refs"]["password_vault_ref"], a["vault_refs"]["password_ref_verification"]],
                        ["Other vault refs", ", ".join(f"{k}={v}" for k, v in a["vault_refs"]["other"].items()) or "-", ""],
                        ["Profile", f"{a['profile']['profile_name']} / bio {a['profile']['bio_char_count']}/150 / {a['profile']['category']}", ""],
                        ["Business account", a["business_account_status"], ""],
                        ["Meta business", f"{a['meta']['link_status']} ({a['meta']['business_ref']})", a["meta"]["verification"]],
                        ["Blocker", (a["blocker"] or {}).get("code") or "-", (a["blocker"] or {}).get("detail") or ""],
                        ["Last verified", a["last_verified_at"], a["verification_source"]],
                    ],
                ),
                "### Provisioning steps",
                "",
                _table(
                    ["Step", "State", "Verification", "Evidence", "Completed"],
                    [[s["step"], s["state"], s["verification"], s["evidence_ref"], s["completed_at"]] for s in a["steps"]],
                ),
                "### People and roles",
                "",
                _table(
                    ["Person", "Platform", "Role", "Status", "Temporary", "Verification", "Last verified"],
                    [
                        [(r["person"] or {}).get("name"), r["platform"], r["role"], r["status"], r["temporary_test_role"], r["verification"], r["last_verified_at"]]
                        for r in a["people_and_roles"]
                    ],
                ),
                "### Open tasks",
                "",
                _table(
                    ["Task", "Owner", "Status", "Due", "Reminders", "Escalations"],
                    [
                        [t["title"], (t["owner"] or {}).get("name"), t["status"], t["due_at"], t["reminder_count"], t["escalation_count"]]
                        for t in a["open_tasks"]
                    ],
                ),
                "### Provisioning gaps",
                "",
                *([f"- {g}" for g in a["provisioning_gaps"]] or ["_None - all steps complete and verified._"]),
                "",
            ]
        return "\n".join(lines)

    def account_register_csv(self, data: dict[str, Any]) -> str:
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            [
                "account_id", "brand", "synthetic", "handle", "status", "owner", "email_hint", "phone_hint",
                "recovery_email", "recovery_email_verification", "recovery_phone", "recovery_phone_verification",
                "two_factor", "two_factor_method", "two_factor_verification", "backup_codes_status",
                "backup_codes_vault_ref", "password_vault_ref", "meta_link", "people_and_roles", "blocker",
                "open_tasks", "last_verified_at",
            ]
        )
        for a in data["accounts"]:
            writer.writerow(
                [
                    a["id"], a["brand_name"], a["is_synthetic"], a["handles"]["selected"], a["provisioning_status"],
                    (a["owner"] or {}).get("name"), a["company_contacts"]["email_hint"], a["company_contacts"]["phone_hint"],
                    a["recovery"]["email_control"], a["recovery"]["email_verification"], a["recovery"]["phone_control"],
                    a["recovery"]["phone_verification"], a["two_factor"]["status"], a["two_factor"]["method"],
                    a["two_factor"]["verification"], a["backup_codes"]["status"], a["backup_codes"]["vault_ref"],
                    a["vault_refs"]["password_vault_ref"], a["meta"]["link_status"],
                    "; ".join(f"{(r['person'] or {}).get('name')}:{r['role']}:{r['status']}" for r in a["people_and_roles"]),
                    (a["blocker"] or {}).get("code") or "", len(a["open_tasks"]), a["last_verified_at"],
                ]
            )
        return buffer.getvalue()

    def write_account_register(self, session: Session, out_dir: Path | None = None) -> list[Path]:
        out_dir = out_dir or self.settings.reports_dir
        data = self.account_register(session)
        paths = [
            self._write_json(out_dir / "account_register.json", data),
            self._write(out_dir / "account_register.md", self.account_register_markdown(data)),
            self._write(out_dir / "account_register.csv", self.account_register_csv(data)),
        ]
        log_event(logger, "report.account_register_written", action="export_report", outcome="written", files=[p.name for p in paths])
        return paths

    # ------------------------------------------------------------------ audit report
    def audit_report(self, session: Session, run: AuditRun) -> dict[str, Any]:
        open_findings = session.scalars(
            select(AuditFinding).where(AuditFinding.status == FindingStatus.OPEN).order_by(AuditFinding.severity, AuditFinding.check_name)
        ).all()
        resolved = session.scalars(
            select(AuditFinding).where(AuditFinding.status == FindingStatus.RESOLVED, AuditFinding.resolution_note.like(f"%{run.id}%"))
        ).all()
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings = sorted((finding_view(f) for f in open_findings), key=lambda f: (severity_rank[f["severity"]], f["check_name"]))
        unresolved = [
            {
                "finding_id": f["id"],
                "severity": f["severity"],
                "description": f["description"],
                "why_unresolved": (
                    f["remediation_blocker"]
                    or ("remediation task " + f["remediation_task"]["status"] if f["remediation_task"] else "no remediation task (informational or transient)")
                ),
            }
            for f in findings
        ]
        return {
            "report_meta": self.report_meta(session, "Weekly security audit report"),
            "audit_run": {
                "id": run.id,
                "trigger": run.trigger.value,
                "idempotency_key": run.idempotency_key,
                "status": run.status.value,
                "started_at": iso(run.started_at),
                "finished_at": iso(run.finished_at),
                "attempt_count": run.attempt_count,
            },
            "totals": (run.summary or {}).get("totals", {}),
            "open_findings": findings,
            "resolved_this_run": [finding_view(f) for f in resolved],
            "check_results": (run.summary or {}).get("accounts", []),
            "unresolved_issues": unresolved,
            "errors": (run.summary or {}).get("errors", []),
        }

    def audit_report_markdown(self, data: dict[str, Any]) -> str:
        meta, run = data["report_meta"], data["audit_run"]
        totals = data["totals"]
        lines = [
            f"# Security audit report - {run['id']}",
            "",
            f"Run: {run['started_at']} -> {run['finished_at']} | trigger: {run['trigger']} | status: {run['status']} | key: {run['idempotency_key'] or '-'}  ",
            f"Data classification: **{meta['data_classification']}**",
            "",
            *[f"> {note}" for note in meta["notes"]],
            "",
            "Verification labels: " + "; ".join(f"**{k}** = {v}" for k, v in LABEL_LEGEND.items()),
            "",
            f"Totals: {totals.get('accounts', 0)} account(s); findings new {totals.get('findings_new', 0)}, "
            f"re-detected (deduplicated) {totals.get('findings_reused', 0)}, resolved {totals.get('findings_resolved', 0)}.",
            "",
            "## Open findings",
            "",
            _table(
                ["Severity", "Check", "Verification", "Description", "Evidence", "Remediation task", "Owner", "Task status", "Due"],
                [
                    [
                        f["severity"], f["check_name"], f["verification"], f["description"], f["evidence_ref"],
                        (f["remediation_task"] or {}).get("id"),
                        ((f["remediation_task"] or {}).get("owner") or {}).get("name"),
                        (f["remediation_task"] or {}).get("status"), (f["remediation_task"] or {}).get("due_at"),
                    ]
                    for f in data["open_findings"]
                ],
            ),
            "## Resolved in this run",
            "",
            _table(["Check", "Description", "Resolved"], [[f["check_name"], f["description"], f["resolved_at"]] for f in data["resolved_this_run"]]),
            "## Check results by account",
            "",
        ]
        for account in data["check_results"]:
            lines += [
                f"### {account['brand_name']} (@{account['handle'] or '-'}){' [SYNTHETIC]' if account['is_synthetic'] else ''}",
                "",
                _table(
                    ["Check", "Outcome", "Verification", "Severity", "Description", "Evidence"],
                    [[c["check_name"], c["outcome"], c["verification"], c["severity"], c["description"], c["evidence_ref"]] for c in account["checks"]],
                ),
            ]
        lines += [
            "## Unresolved issues",
            "",
            *([f"- [{u['severity']}] {u['description']} - {u['why_unresolved']}" for u in data["unresolved_issues"]] or ["_None._"]),
            "",
        ]
        if data["errors"]:
            lines += ["## Errors during this run", "", *[f"- {e['account_id']}: {e['error']}" for e in data["errors"]], ""]
        return "\n".join(lines)

    def write_audit_report(self, session: Session, run: AuditRun, *, latest: bool = False) -> tuple[str, str]:
        """Timestamped report per run (history); ``latest=True`` writes the stable 'current state' copy."""
        data = self.audit_report(session, run)
        name = "audit_report_latest" if latest else f"audit_report_{self._stamp()}_{run.id}"
        base = self.settings.reports_dir / "audit" / name
        json_path = self._write_json(base.with_suffix(".json"), data)
        md_path = self._write(base.with_suffix(".md"), self.audit_report_markdown(data))
        log_event(logger, "report.audit_written", action="export_report", outcome="written", audit_run_id=run.id)
        return str(json_path), str(md_path)

    # ------------------------------------------------------------------ offboarding report
    def offboarding_report(self, session: Session, case: OffboardingCase) -> dict[str, Any]:
        view = case_view(case)
        risks: list[str] = []
        name = (view["person"] or {}).get("name")
        for action in case.actions:
            if action.status in (OffboardingActionStatus.COMPLETED, OffboardingActionStatus.CANCELLED):
                continue
            state = "blocked" if action.status == OffboardingActionStatus.BLOCKED else "pending"
            if action.action_type == OffboardingActionType.REMOVE_ACCOUNT_ROLE:
                risks.append(f"{name} may still hold access ({action.description}) until removal is confirmed [{state}]")
            elif action.action_type == OffboardingActionType.ROTATE_CREDENTIAL:
                risks.append(f"Credential {action.detail.get('vault_ref', action.target_ref)} may still be known to {name} until rotated [{state}]")
            elif action.action_type == OffboardingActionType.REPLACE_BACKUP_CODES:
                risks.append(f"Backup codes ({action.detail.get('vault_ref', action.target_ref)}) may be exposed until replaced [{state}]")
            elif action.action_type == OffboardingActionType.REMOVE_VAULT_ACCESS:
                risks.append(f"{name} may still be able to read vault entry {action.detail.get('vault_ref', action.target_ref)} [{state}]")
            elif action.action_type == OffboardingActionType.REVOKE_APP_ACCESS:
                risks.append(f"{name} still has access to this operations application [{state}]")
            elif action.action_type == OffboardingActionType.GRANT_REPLACEMENT_ADMIN:
                risks.append(f"Replacement admin not yet confirmed; the departing admin's role cannot be removed safely [{state}]")
            elif action.action_type == OffboardingActionType.VERIFY_ACCESS_STATE:
                risks.append(f"No independent verification of the final access state yet [{state}]")
        return {"report_meta": self.report_meta(session, "Offboarding report"), "case": view, "outstanding_risks": risks}

    def offboarding_report_markdown(self, data: dict[str, Any]) -> str:
        meta, case = data["report_meta"], data["case"]

        system_actions = {"revoke_app_access", "identify_roles", "identify_credentials", "update_register"}

        def rows(actions: list[dict[str, Any]], kind: str) -> list[list[Any]]:
            out = []
            for a in actions:
                owner = (a["owner"] or {}).get("name") or ("system (this application)" if a["action_type"] in system_actions else "-")
                task = a["task"] or {}
                if kind == "completed":
                    out.append([a["action_type"], a["description"], owner, a["verification"], a["evidence_ref"], a["completed_at"]])
                elif kind == "pending":
                    waiting = (a["detail"] or {}).get("waiting_on")
                    task_ref = task.get("id") or (f"waiting on {len(waiting)} prerequisite action(s)" if waiting else "waiting on prerequisites")
                    out.append([a["action_type"], a["description"], owner, task_ref, task.get("status", "-"), task.get("due_at", "-")])
                else:
                    out.append([a["action_type"], a["description"], owner, a["blocker_code"], a["blocker_detail"]])
            return out

        return "\n".join(
            [
                f"# Offboarding report - {(case['person'] or {}).get('name')}",
                "",
                f"Case {case['id']} | status: **{case['status']}** | opened {case['created_at']} | reason: {case['reason']}  ",
                f"Replacement admin: {(case['replacement_admin'] or {}).get('name') or '-'} | reconciliations run: {case['reconcile_count']}  ",
                f"Data classification: **{meta['data_classification']}**",
                "",
                *[f"> {note}" for note in meta["notes"]],
                "",
                "A pending action means a task exists; it does NOT mean access has been removed.",
                "",
                f"## Completed ({len(case['completed'])})",
                "",
                _table(["Action", "Description", "Owner", "Verification", "Evidence", "Completed"], rows(case["completed"], "completed")),
                f"## Pending ({len(case['pending'])})",
                "",
                _table(["Action", "Description", "Owner", "Task", "Task status", "Due"], rows(case["pending"], "pending")),
                f"## Blocked ({len(case['blocked'])})",
                "",
                _table(["Action", "Description", "Responsible owner", "Blocker", "Detail"], rows(case["blocked"], "blocked")),
                "## Outstanding risks",
                "",
                *([f"- {r}" for r in data["outstanding_risks"]] or ["_None - all actions completed._"]),
                "",
            ]
        )

    def write_offboarding_report(self, session: Session, case: OffboardingCase) -> tuple[str, str]:
        """One file per case, rewritten on each export (the generation time is inside the report)."""
        data = self.offboarding_report(session, case)
        base = self.settings.reports_dir / "offboarding" / f"offboarding_report_{case.id}"
        json_path = self._write_json(base.with_suffix(".json"), data)
        md_path = self._write(base.with_suffix(".md"), self.offboarding_report_markdown(data))
        log_event(logger, "report.offboarding_written", action="export_report", outcome="written", case_id=case.id)
        return str(json_path), str(md_path)

    # ------------------------------------------------------------------ run log
    def export_run_log(self, out_dir: Path | None = None) -> Path:
        """Copy the run log with a second redaction pass (defence in depth)."""
        out_dir = out_dir or self.settings.reports_dir
        source = self.settings.log_dir / RUN_LOG_FILENAME
        lines: list[str] = []
        if source.exists():
            for raw in source.read_text(encoding="utf-8").splitlines():
                if not raw.strip():
                    continue
                try:
                    record = json.loads(raw)
                except json.JSONDecodeError:
                    record = {"event": "unparseable_log_line", "message": raw}
                lines.append(json.dumps(self.redactor.redact(record), ensure_ascii=False, default=str))
        return self._write(out_dir / "run_log_redacted.jsonl", "\n".join(lines) + ("\n" if lines else ""))

    def export_all(self, session: Session) -> dict[str, Any]:
        written: dict[str, Any] = {"account_register": [str(p) for p in self.write_account_register(session)]}
        latest = session.scalar(select(AuditRun).order_by(AuditRun.started_at.desc()).limit(1))
        if latest is not None:
            written["audit_report_latest"] = list(self.write_audit_report(session, latest, latest=True))
        written["offboarding_reports"] = [
            list(self.write_offboarding_report(session, case))
            for case in session.scalars(select(OffboardingCase).order_by(OffboardingCase.created_at))
        ]
        written["run_log"] = str(self.export_run_log())
        written["generated_at"] = datetime.now().astimezone().isoformat()
        return written
