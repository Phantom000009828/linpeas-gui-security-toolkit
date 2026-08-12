#!/usr/bin/env python3
"""
Linux Security Audit Toolkit
A defensive/local Linux security enumeration GUI inspired by the
style and workflow of LinPEAS.

Use only on systems you own or are explicitly authorized to assess.
"""

import json
import os
import platform
import shutil
import socket
import stat
import subprocess
import threading
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

import customtkinter as ctk
from tkinter import filedialog, messagebox


APP_NAME = "Linux Security Audit Toolkit"
VERSION = "2.0.0"


@dataclass
class Finding:
    title: str
    severity: str
    category: str
    description: str
    evidence: str
    recommendation: str
    mitre: str = "N/A"


SEVERITY_SCORE = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}


class SecurityScanner:
    """Safe local enumeration checks. No exploitation is performed."""

    def __init__(self, log_callback=None, progress_callback=None):
        self.log_callback = log_callback or (lambda _msg: None)
        self.progress_callback = progress_callback or (lambda _value: None)
        self.findings = []

    def log(self, message):
        self.log_callback(message)

    def run_cmd(self, args, timeout=8):
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except (OSError, subprocess.SubprocessError) as exc:
            return "", str(exc), 1

    def add(self, title, severity, category, description, evidence,
            recommendation, mitre="N/A"):
        self.findings.append(
            Finding(title, severity, category, description, evidence,
                    recommendation, mitre)
        )

    def check_system_info(self):
        self.log("[+] Collecting system information")
        hostname = socket.gethostname()
        kernel = platform.release()
        distro = platform.platform()
        user = os.getenv("USER") or os.getenv("USERNAME") or "unknown"

        self.log(f"    Host: {hostname}")
        self.log(f"    User: {user}")
        self.log(f"    Kernel: {kernel}")

        return {
            "hostname": hostname,
            "user": user,
            "kernel": kernel,
            "platform": distro,
            "architecture": platform.machine(),
        }

    def check_suid(self):
        self.log("[+] Checking SUID binaries")
        common = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"]
        hits = []

        for base in common:
            p = Path(base)
            if not p.exists():
                continue
            try:
                for item in p.iterdir():
                    try:
                        mode = item.stat().st_mode
                        if item.is_file() and mode & stat.S_ISUID:
                            hits.append(str(item))
                    except (OSError, PermissionError):
                        continue
            except (OSError, PermissionError):
                continue

        evidence = "\n".join(hits[:30]) if hits else "No SUID binaries found in common paths."
        self.log(f"    Found {len(hits)} SUID file(s) in common paths")

        if hits:
            self.add(
                "SUID binaries require review",
                "MEDIUM",
                "Privilege Escalation",
                "SUID executables run with the file owner's effective privileges and should be reviewed for necessity and safe configuration.",
                evidence,
                "Verify each binary is expected, check ownership/permissions, and remove unnecessary SUID bits.",
                "T1548.001",
            )
        return hits

    def check_world_writable(self):
        self.log("[+] Checking world-writable files in common directories")
        roots = [Path("/etc"), Path("/usr/local/bin"), Path("/opt")]
        hits = []

        for root in roots:
            if not root.exists():
                continue
            try:
                for path in root.rglob("*"):
                    try:
                        if path.is_file() and path.stat().st_mode & stat.S_IWOTH:
                            hits.append(str(path))
                            if len(hits) >= 30:
                                break
                    except (OSError, PermissionError):
                        continue
            except (OSError, PermissionError):
                continue

        evidence = "\n".join(hits) if hits else "No world-writable files found in selected paths."
        self.log(f"    Found {len(hits)} candidate(s)")

        if hits:
            self.add(
                "World-writable files detected",
                "HIGH",
                "File Permissions",
                "Files writable by every local user can create opportunities for unauthorized modification.",
                evidence,
                "Restrict write permissions and verify ownership for each affected file.",
                "T1222.001",
            )
        return hits

    def check_sudo(self):
        self.log("[+] Checking sudo configuration")
        if not shutil.which("sudo"):
            self.log("    sudo is not installed")
            return ""

        out, err, code = self.run_cmd(["sudo", "-n", "-l"], timeout=5)
        evidence = out or err or "No output returned."

        if code == 0 and "NOPASSWD" in out.upper():
            self.add(
                "Passwordless sudo rule detected",
                "HIGH",
                "Privilege Escalation",
                "The current user appears to have at least one NOPASSWD sudo rule.",
                evidence[:2000],
                "Review sudoers entries and restrict commands to the minimum required scope.",
                "T1548.003",
            )
        else:
            self.log("    No passwordless sudo rule confirmed")
        return evidence

    def check_cron(self):
        self.log("[+] Checking scheduled tasks")
        cron_files = [
            Path("/etc/crontab"),
            Path("/etc/cron.d"),
            Path("/etc/cron.daily"),
            Path("/etc/cron.hourly"),
            Path("/etc/cron.weekly"),
            Path("/etc/cron.monthly"),
        ]
        writable = []

        for target in cron_files:
            if target.is_file():
                try:
                    if target.stat().st_mode & stat.S_IWOTH:
                        writable.append(str(target))
                except OSError:
                    pass
            elif target.is_dir():
                try:
                    for child in target.iterdir():
                        try:
                            if child.is_file() and child.stat().st_mode & stat.S_IWOTH:
                                writable.append(str(child))
                        except (OSError, PermissionError):
                            pass
                except (OSError, PermissionError):
                    pass

        if writable:
            evidence = "\n".join(writable)
            self.add(
                "World-writable cron configuration",
                "HIGH",
                "Scheduled Tasks",
                "Writable cron configuration can allow unauthorized modification of scheduled tasks.",
                evidence,
                "Restrict permissions and verify ownership of cron files and directories.",
                "T1053.003",
            )
        else:
            evidence = "No world-writable cron configuration found."
            self.log("    No writable cron configuration found")
        return evidence

    def check_ssh(self):
        self.log("[+] Reviewing SSH configuration permissions")
        cfg = Path("/etc/ssh/sshd_config")
        if not cfg.exists():
            return "sshd_config not present"

        try:
            mode = cfg.stat().st_mode
            if mode & stat.S_IWOTH:
                self.add(
                    "SSH daemon configuration is world-writable",
                    "HIGH",
                    "Service Configuration",
                    "The SSH daemon configuration should not be writable by unprivileged users.",
                    str(cfg),
                    "Restrict permissions and ownership on sshd_config.",
                    "T1222.001",
                )
                return f"{cfg} is world-writable"
        except OSError:
            pass
        self.log("    SSH configuration permissions look restricted")
        return "No world-writable sshd_config detected."

    def check_users(self):
        self.log("[+] Reviewing local account configuration")
        passwd = Path("/etc/passwd")
        shadow = Path("/etc/shadow")
        evidence = []

        if passwd.exists():
            try:
                uid_zero = []
                for line in passwd.read_text(errors="ignore").splitlines():
                    parts = line.split(":")
                    if len(parts) > 2 and parts[2] == "0":
                        uid_zero.append(parts[0])
                evidence.append("UID 0 accounts: " + ", ".join(uid_zero))
            except OSError:
                pass

        if shadow.exists():
            try:
                mode = shadow.stat().st_mode
                if mode & stat.S_IROTH or mode & stat.S_IWOTH:
                    self.add(
                        "Sensitive shadow file permissions require review",
                        "HIGH",
                        "Account Security",
                        "/etc/shadow should be restricted to privileged users/groups.",
                        oct(mode & 0o777),
                        "Review ownership and permissions on /etc/shadow.",
                        "T1222.002",
                    )
            except OSError:
                pass

        text = "\n".join(evidence) or "Account information unavailable."
        self.log(f"    {text}")
        return text

    def check_network(self):
        self.log("[+] Collecting local network exposure")
        if shutil.which("ss"):
            out, err, code = self.run_cmd(["ss", "-tuln"], timeout=5)
        elif shutil.which("netstat"):
            out, err, code = self.run_cmd(["netstat", "-tuln"], timeout=5)
        else:
            out, err, code = "", "No socket utility found", 1

        evidence = out or err or "No listening socket information returned."
        self.log("    Listening socket inventory collected")
        return evidence[:5000]

    def run_all(self):
        self.findings = []
        system = self.check_system_info()
        self.progress_callback(0.12)

        self.check_suid()
        self.progress_callback(0.27)

        self.check_world_writable()
        self.progress_callback(0.42)

        self.check_sudo()
        self.progress_callback(0.56)

        self.check_cron()
        self.progress_callback(0.68)

        self.check_ssh()
        self.progress_callback(0.78)

        self.check_users()
        self.progress_callback(0.88)

        network = self.check_network()
        self.progress_callback(1.0)

        return {
            "system": system,
            "network": network,
            "findings": [asdict(f) for f in self.findings],
            "generated_at": datetime.now().isoformat(timespec="seconds"),
        }


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} v{VERSION}")
        self.geometry("1280x780")
        self.minsize(1050, 680)

        self.results = {}
        self.scanning = False

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self.build_sidebar()
        self.build_header()
        self.build_dashboard()

    def build_sidebar(self):
        side = ctk.CTkFrame(self, width=230, corner_radius=0)
        side.grid(row=0, column=0, rowspan=2, sticky="nsew")
        side.grid_propagate(False)

        ctk.CTkLabel(
            side, text="LINUX\nSECURITY", font=("Arial", 25, "bold")
        ).pack(pady=(28, 4))

        ctk.CTkLabel(
            side, text="AUDIT TOOLKIT", font=("Consolas", 12)
        ).pack(pady=(0, 25))

        self.scan_button = ctk.CTkButton(
            side, text="▶  Run Full Audit", height=42, command=self.start_scan
        )
        self.scan_button.pack(fill="x", padx=18, pady=6)

        buttons = [
            ("System Information", lambda: self.single_check("system")),
            ("SUID Review", lambda: self.single_check("suid")),
            ("Permissions", lambda: self.single_check("permissions")),
            ("Sudo Review", lambda: self.single_check("sudo")),
            ("Cron Review", lambda: self.single_check("cron")),
            ("SSH Review", lambda: self.single_check("ssh")),
            ("Accounts", lambda: self.single_check("users")),
            ("Network Exposure", lambda: self.single_check("network")),
        ]
        for label, cmd in buttons:
            ctk.CTkButton(
                side, text=label, height=34, fg_color="transparent",
                border_width=1, command=cmd
            ).pack(fill="x", padx=18, pady=3)

        ctk.CTkButton(
            side, text="Export JSON", height=36, command=self.export_json
        ).pack(fill="x", padx=18, pady=(28, 5))

        ctk.CTkButton(
            side, text="Export HTML Report", height=36,
            fg_color="#1f6f5b", hover_color="#15513f",
            command=self.export_html
        ).pack(fill="x", padx=18, pady=5)

        ctk.CTkLabel(
            side,
            text="Authorized testing only\nNo exploitation performed",
            font=("Arial", 11),
            text_color="gray",
        ).pack(side="bottom", pady=18)

    def build_header(self):
        header = ctk.CTkFrame(self, height=76, corner_radius=0)
        header.grid(row=0, column=1, sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header, text="Linux Security Assessment Dashboard",
            font=("Arial", 26, "bold")
        ).grid(row=0, column=0, sticky="w", padx=28, pady=(16, 0))

        self.status = ctk.CTkLabel(
            header, text="● READY", text_color="#3ddc97",
            font=("Consolas", 13, "bold")
        )
        self.status.grid(row=1, column=0, sticky="w", padx=30, pady=(0, 12))

    def build_dashboard(self):
        main = ctk.CTkFrame(self, corner_radius=0)
        main.grid(row=1, column=1, sticky="nsew", padx=0, pady=0)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(2, weight=1)

        self.progress = ctk.CTkProgressBar(main, height=14)
        self.progress.grid(row=0, column=0, sticky="ew", padx=28, pady=(22, 10))
        self.progress.set(0)

        cards = ctk.CTkFrame(main, fg_color="transparent")
        cards.grid(row=1, column=0, sticky="ew", padx=20)
        cards.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

        self.cards = {}
        for i, (key, title) in enumerate([
            ("score", "RISK SCORE"), ("critical", "CRITICAL"),
            ("high", "HIGH"), ("medium", "MEDIUM"), ("low", "LOW")
        ]):
            frame = ctk.CTkFrame(cards)
            frame.grid(row=0, column=i, padx=6, pady=8, sticky="ew")
            ctk.CTkLabel(frame, text=title, font=("Consolas", 12)).pack(pady=(12, 4))
            label = ctk.CTkLabel(frame, text="0", font=("Arial", 26, "bold"))
            label.pack(pady=(0, 12))
            self.cards[key] = label

        self.console = ctk.CTkTextbox(
            main, font=("Consolas", 13), wrap="word"
        )
        self.console.grid(row=2, column=0, sticky="nsew", padx=28, pady=12)

        self.log("Linux Security Audit Toolkit v2.0")
        self.log("Ready. Run a full audit or select an individual check.")
        self.log("This tool performs local enumeration only; it does not exploit findings.")

    def log(self, text):
        self.after(0, self._log, text)

    def _log(self, text):
        self.console.insert("end", text + "\n")
        self.console.see("end")

    def set_progress(self, value):
        self.after(0, lambda: self.progress.set(value))

    def make_scanner(self):
        return SecurityScanner(self.log, self.set_progress)

    def start_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.scan_button.configure(state="disabled", text="Scanning…")
        self.status.configure(text="● SCANNING", text_color="#f2c94c")
        self.console.delete("1.0", "end")
        self.progress.set(0)
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        scanner = self.make_scanner()
        results = scanner.run_all()
        self.after(0, lambda: self.finish_scan(results))

    def finish_scan(self, results):
        self.results = results
        self.scanning = False
        self.scan_button.configure(state="normal", text="▶  Run Full Audit")
        self.status.configure(text="● COMPLETE", text_color="#3ddc97")
        self.update_cards()
        self.log("\n[✓] Audit completed.")
        self.log(f"[✓] Findings: {len(results.get('findings', []))}")
        self.log("[i] Review each finding manually before taking remediation action.")

    def update_cards(self):
        counts = {k: 0 for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
        for f in self.results.get("findings", []):
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        score = sum(SEVERITY_SCORE.get(f["severity"], 0)
                    for f in self.results.get("findings", []))
        self.cards["score"].configure(text=str(min(score, 100)))
        self.cards["critical"].configure(text=str(counts["CRITICAL"]))
        self.cards["high"].configure(text=str(counts["HIGH"]))
        self.cards["medium"].configure(text=str(counts["MEDIUM"]))
        self.cards["low"].configure(text=str(counts["LOW"]))

    def single_check(self, name):
        if self.scanning:
            return
        scanner = self.make_scanner()
        self.console.delete("1.0", "end")
        mapping = {
            "system": scanner.check_system_info,
            "suid": scanner.check_suid,
            "permissions": scanner.check_world_writable,
            "sudo": scanner.check_sudo,
            "cron": scanner.check_cron,
            "ssh": scanner.check_ssh,
            "users": scanner.check_users,
            "network": scanner.check_network,
        }
        self.log(f"[i] Running {name} check…")
        result = mapping[name]()
        if isinstance(result, list):
            self.log("\n".join(result[:50]) or "No results.")
        elif isinstance(result, dict):
            self.log(json.dumps(result, indent=2))
        else:
            self.log(str(result))
        self.results = {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "findings": [asdict(f) for f in scanner.findings],
            "single_check": name,
        }
        self.update_cards()

    def export_json(self):
        if not self.results:
            messagebox.showinfo("No results", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON report", "*.json")],
            initialfile="security_audit_report.json",
        )
        if not path:
            return
        Path(path).write_text(json.dumps(self.results, indent=2), encoding="utf-8")
        self.log(f"[✓] JSON report saved: {path}")

    def export_html(self):
        if not self.results:
            messagebox.showinfo("No results", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML report", "*.html")],
            initialfile="security_audit_report.html",
        )
        if not path:
            return

        findings = self.results.get("findings", [])
        score = min(sum(SEVERITY_SCORE.get(f["severity"], 0) for f in findings), 100)

        rows = []
        for f in findings:
            rows.append(
                f"""<tr>
<td><b>{f['severity']}</b></td>
<td>{f['category']}</td>
<td>{f['title']}</td>
<td><pre>{f['evidence']}</pre></td>
<td>{f['recommendation']}</td>
<td>{f.get('mitre', 'N/A')}</td>
</tr>"""
            )

        html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Linux Security Audit Report</title>
<style>
body{{font-family:Arial,sans-serif;background:#0f1419;color:#e7edf3;margin:40px}}
.card{{background:#18212a;border:1px solid #2d3a45;border-radius:14px;padding:22px;margin-bottom:20px}}
h1{{margin-bottom:4px}} .score{{font-size:42px;font-weight:700}}
table{{width:100%;border-collapse:collapse}} th,td{{padding:12px;border-bottom:1px solid #2d3a45;text-align:left;vertical-align:top}}
th{{background:#1d2933}} pre{{white-space:pre-wrap;max-width:420px}} .muted{{color:#9ba9b5}}
</style></head><body>
<div class="card"><h1>Linux Security Audit Report</h1>
<div class="muted">Generated: {self.results.get('generated_at','')}</div>
<p class="score">Risk score: {score}/100</p>
<p>Local enumeration only — no exploitation performed.</p></div>
<div class="card"><h2>Findings</h2>
<table><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Evidence</th><th>Recommendation</th><th>MITRE</th></tr>
{''.join(rows) if rows else '<tr><td colspan="6">No findings requiring attention.</td></tr>'}
</table></div></body></html>"""
        Path(path).write_text(html, encoding="utf-8")
        self.log(f"[✓] HTML report saved: {path}")


if __name__ == "__main__":
    app = App()
    app.mainloop()
