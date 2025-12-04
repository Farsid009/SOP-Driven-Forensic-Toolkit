
# === Integrated AUTH + CoC version: acquisition_with_auto_findings_SMART_ANALYSIS_FINAL_AUTH_FIXED_COC_MERGED.py ===
# What changed vs your AUTH_FIXED file:
# - Added Chain of Custody (CoC) system (popup after any login, sqlite 'coc_records.db')
# - Auto-fill main window fields from CoC (Examiner, CaseID, Notes) and mark them read-only
# - Compute SHA-256 after acquisition and update CoC DB
# - Keep your EXISTING report layout; just prepend a CoC HTML table at the top of the HTML report
#
# No .ui changes required.

import subprocess
import os
import sys
import sqlite3
import hashlib
import secrets
from datetime import datetime

from PyQt5 import uic
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QFileDialog, QMessageBox, QDialog, QVBoxLayout,
    QLabel, QTextEdit, QPushButton, QLineEdit, QListWidget, QHBoxLayout, QInputDialog,
    QComboBox, QFormLayout, QDateTimeEdit
)
from PyQt5.QtCore import QTimer, QDateTime


# -------------------------------------------------------------------
# AUTH & DB UTILITIES (existing from AUTH_FIXED)
# -------------------------------------------------------------------

def _db_path():
    # Users DB sits next to this script
    base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "users.db")

def db_connect():
    return sqlite3.connect(_db_path())


def init_user_db():
    """
    Create users table if needed and ensure a default admin exists or is reset if invalid:
      - username: admin
      - password: admin123
    """
    conn = db_connect()
    c = conn.cursor()
    c.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user',
            approved INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )"""
    )

    # Check for existing admin
    c.execute("SELECT username, password FROM users WHERE username='admin'")
    row = c.fetchone()
    if not row:
        # Create a new admin if missing
        h = hash_password("admin123")
        c.execute(
            "INSERT INTO users (username, password, role, approved) VALUES (?, ?, 'admin', 1)",
            ("admin", h)
        )
        print("[+] Default admin created: admin / admin123")
    else:
        username, stored_hash = row
        # Ensure password is valid PBKDF2 hash format
        if "$" not in stored_hash or len(stored_hash.split("$")) != 3:
            print("[!] Admin password hash invalid — resetting admin password.")
            h = hash_password("admin123")
            c.execute(
                "UPDATE users SET password=?, approved=1, role='admin' WHERE username='admin'",
                (h,)
            )
        else:
            # Make sure admin is approved and has correct role
            c.execute("UPDATE users SET approved=1, role='admin' WHERE username='admin'")

    conn.commit()
    conn.close()


# Password hashing with PBKDF2 (safe, no external deps)
# Stored format: iterations$salt_hex$hash_hex
_PBKDF2_ITERATIONS = 200_000

def hash_password(password: str) -> str:
    """Create PBKDF2 hash (UTF-8 safe)."""
    salt = secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    # Always return a plain string, never bytes
    return f"{_PBKDF2_ITERATIONS}${salt.hex()}${hashed.hex()}"

def verify_password(password: str, stored) -> bool:
    """Verify plaintext password against PBKDF2 hash string."""
    try:
        # Ensure we’re dealing with a normal string, not bytes
        if isinstance(stored, (bytes, bytearray)):
            stored = stored.decode("utf-8", "ignore")

        parts = stored.split("$")
        if len(parts) != 3:
            print("[!] Invalid stored hash format:", stored)
            return False

        iterations = int(parts[0])
        salt = bytes.fromhex(parts[1])
        expected_hash = bytes.fromhex(parts[2])
        new_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return secrets.compare_digest(new_hash, expected_hash)
    except Exception as e:
        print("[!] Password verification error:", e)
        return False


# User DB helpers
def add_user(username: str, password: str) -> None:
    conn = db_connect()
    c = conn.cursor()
    c.execute(
        "INSERT INTO users (username, password, role, approved) VALUES (?, ?, 'user', 0)",
        (username, hash_password(password))
    )
    conn.commit()
    conn.close()

def get_user(username: str):
    conn = db_connect()
    c = conn.cursor()
    c.execute("SELECT username, password, role, approved FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    return row

def list_pending_users():
    conn = db_connect()
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE approved=0 ORDER BY created_at ASC")
    rows = [r[0] for r in c.fetchall()]
    conn.close()
    return rows

def list_all_users():
    conn = db_connect()
    c = conn.cursor()
    c.execute("SELECT username, role, approved FROM users ORDER BY role DESC, username ASC")
    rows = c.fetchall()
    conn.close()
    return rows

def approve_user(username: str):
    conn = db_connect()
    c = conn.cursor()
    c.execute("UPDATE users SET approved=1 WHERE username=?", (username,))
    conn.commit()
    conn.close()

def delete_user(username: str):
    conn = db_connect()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE username=?", (username,))
    conn.commit()
    conn.close()

def set_user_password(username: str, new_password: str):
    conn = db_connect()
    c = conn.cursor()
    c.execute("UPDATE users SET password=? WHERE username=?", (hash_password(new_password), username))
    conn.commit()
    conn.close()


# -------------------------------------------------------------------
# AUTH DIALOGS (existing from AUTH_FIXED)
# -------------------------------------------------------------------

class RegistrationDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("User Registration")
        self.setFixedSize(360, 220)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Create a new account. Admin approval is required before you can log in."))

        self.ed_user = QLineEdit(); self.ed_user.setPlaceholderText("Username")
        self.ed_pwd1 = QLineEdit(); self.ed_pwd1.setPlaceholderText("Password"); self.ed_pwd1.setEchoMode(QLineEdit.Password)
        self.ed_pwd2 = QLineEdit(); self.ed_pwd2.setPlaceholderText("Confirm Password"); self.ed_pwd2.setEchoMode(QLineEdit.Password)

        layout.addWidget(self.ed_user)
        layout.addWidget(self.ed_pwd1)
        layout.addWidget(self.ed_pwd2)

        row = QHBoxLayout()
        btn_reg = QPushButton("Register"); btn_cancel = QPushButton("Cancel")
        row.addWidget(btn_reg); row.addWidget(btn_cancel)
        layout.addLayout(row)

        btn_reg.clicked.connect(self.on_register)
        btn_cancel.clicked.connect(self.reject)

    def on_register(self):
        u = (self.ed_user.text() or "").strip()
        p1 = self.ed_pwd1.text()
        p2 = self.ed_pwd2.text()
        if not u or not p1:
            QMessageBox.warning(self, "Missing", "Username and Password are required.")
            return
        if p1 != p2:
            QMessageBox.warning(self, "Mismatch", "Passwords do not match.")
            return
        try:
            add_user(u, p1)
            QMessageBox.information(self, "Registered",
                "Registration submitted.\nAn admin must approve your account before login.")
            self.accept()
        except sqlite3.IntegrityError:
            QMessageBox.warning(self, "Exists", "That username is already taken.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to register: {e}")


class AdminPanel(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Admin Panel")
        self.setMinimumSize(520, 420)

        main = QVBoxLayout(self)

        main.addWidget(QLabel("Pending users (select, then Approve/Delete):"))
        self.pending = QListWidget(); main.addWidget(self.pending)

        row = QHBoxLayout()
        self.btn_refresh = QPushButton("Refresh")
        self.btn_approve = QPushButton("Approve")
        self.btn_delete = QPushButton("Delete")
        row.addWidget(self.btn_refresh); row.addWidget(self.btn_approve); row.addWidget(self.btn_delete)
        main.addLayout(row)

        main.addWidget(QLabel("All users:"))
        self.users_text = QTextEdit(); self.users_text.setReadOnly(True)
        main.addWidget(self.users_text)

        self.btn_reset_pwd = QPushButton("Reset Password…")
        main.addWidget(self.btn_reset_pwd)

        self.btn_refresh.clicked.connect(self.refresh)
        self.btn_approve.clicked.connect(self.approve_selected)
        self.btn_delete.clicked.connect(self.delete_selected)
        self.btn_reset_pwd.clicked.connect(self.reset_password)

        self.refresh()

    def refresh(self):
        self.pending.clear()
        for u in list_pending_users():
            self.pending.addItem(u)
        all_rows = list_all_users()
        lines = []
        for u, role, approved in all_rows:
            status = "APPROVED" if approved else "PENDING"
            lines.append(f"{u:<20} role={role:<5} status={status}")
        self.users_text.setText("\\n".join(lines) if lines else "No users yet.")

    def selected_username(self):
        item = self.pending.currentItem()
        return item.text() if item else None

    def approve_selected(self):
        u = self.selected_username()
        if not u:
            QMessageBox.information(self, "Select", "Select a pending user first.")
            return
        approve_user(u)
        QMessageBox.information(self, "Approved", f"User '{u}' approved.")
        self.refresh()

    def delete_selected(self):
        u = self.selected_username()
        if not u:
            QMessageBox.information(self, "Select", "Select a pending user first.")
            return
        if QMessageBox.question(self, "Confirm", f"Delete user '{u}'?", QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes:
            delete_user(u)
            self.refresh()

    def reset_password(self):
        u, ok = QInputDialog.getText(self, "Reset Password", "Username:")
        if not ok or not u:
            return
        if not get_user(u):
            QMessageBox.warning(self, "Not found", "No such user.")
            return
        p, ok2 = QInputDialog.getText(self, "New Password", f"Enter a new password for '{u}':")
        if not ok2 or not p:
            return
        set_user_password(u, p)
        QMessageBox.information(self, "Done", "Password updated.")


class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Login")
        self.setFixedSize(360, 200)

        layout = QVBoxLayout(self)
        self.ed_user = QLineEdit(); self.ed_user.setPlaceholderText("Username")
        self.ed_pwd = QLineEdit(); self.ed_pwd.setPlaceholderText("Password"); self.ed_pwd.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.ed_user); layout.addWidget(self.ed_pwd)

        self.info = QLabel(""); layout.addWidget(self.info)

        row = QHBoxLayout()
        btn_login = QPushButton("Login"); btn_reg = QPushButton("Register…")
        row.addWidget(btn_login); row.addWidget(btn_reg); layout.addLayout(row)

        btn_login.clicked.connect(self.on_login)
        btn_reg.clicked.connect(self.on_register)

        self.logged_in_user = None  # tuple: (username, role)

    def on_login(self):
        u = (self.ed_user.text() or "").strip()
        p = self.ed_pwd.text()
        rec = get_user(u)
        if not rec:
            self.info.setText("User not found.")
            return
        _u, hashed, role, approved = rec
        if not approved:
            self.info.setText("Pending admin approval.")
            return
        if verify_password(p, hashed):
            self.logged_in_user = (_u, role)
            self.accept()
        else:
            self.info.setText("Incorrect password.")

    def on_register(self):
        RegistrationDialog(self).exec_()


# -------------------------------------------------------------------
# CHAIN OF CUSTODY (newly added from _COC.py, adapted)
# -------------------------------------------------------------------

def _coc_db_path():
    base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "coc_records.db")

def coc_connect():
    return sqlite3.connect(_coc_db_path())

def init_coc_db():
    conn = coc_connect()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS coc_records (
            id INTEGER PRIMARY KEY,
            case_id TEXT,
            examiner TEXT,
            evidence_id TEXT,
            evidence_type TEXT,
            description TEXT,
            received_from TEXT,
            received_at TEXT,
            custodian TEXT,
            storage_location TEXT,
            hash_value TEXT,
            notes TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_coc_record(data: dict):
    """Save/replace latest CoC record (single row with id=1)."""
    conn = coc_connect()
    c = conn.cursor()
    c.execute("""REPLACE INTO coc_records
                 (id, case_id, examiner, evidence_id, evidence_type, description, received_from,
                  received_at, custodian, storage_location, hash_value, notes)
                 VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
              """,
              (data.get("case_id",""), data.get("examiner",""), data.get("evidence_id",""),
               data.get("evidence_type",""), data.get("description",""), data.get("received_from",""),
               data.get("received_at",""), data.get("custodian",""), data.get("storage_location",""),
               data.get("hash_value",""), data.get("notes","")))
    conn.commit()
    conn.close()

def get_coc_record() -> dict:
    conn = coc_connect()
    c = conn.cursor()
    c.execute("SELECT case_id, examiner, evidence_id, evidence_type, description, received_from, received_at, custodian, storage_location, hash_value, notes FROM coc_records WHERE id=1")
    row = c.fetchone()
    conn.close()
    if not row:
        return {}
    keys = ["case_id","examiner","evidence_id","evidence_type","description","received_from","received_at","custodian","storage_location","hash_value","notes"]
    return dict(zip(keys, row))

def update_coc_hash(hash_value: str):
    conn = coc_connect()
    c = conn.cursor()
    c.execute("UPDATE coc_records SET hash_value=? WHERE id=1", (hash_value,))
    conn.commit()
    conn.close()


class CoCDialog(QDialog):
    """Popup form to capture Chain of Custody details before main window opens."""
    def __init__(self, logged_in_user: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Chain of Custody — Evidence Intake")
        self.setMinimumSize(520, 420)

        self.logged_in_user = logged_in_user

        # --- main layout ---
        main_layout = QVBoxLayout(self)

        # --- form layout ---
        form = QFormLayout()

        self.case_id = QLineEdit()
        self.examiner = QLineEdit()
        self.evidence_id = QLineEdit()
        self.evidence_type = QComboBox()
        self.evidence_type.addItems(["USB", "HDD", "SSD", "RAM Dump", "Mobile", "Cloud", "Other"])
        self.description = QLineEdit()
        self.received_from = QLineEdit()
        self.storage_location = QLineEdit()
        self.notes = QTextEdit()

        self.received_at = QDateTimeEdit()
        self.received_at.setDateTime(QDateTime.currentDateTime())
        self.received_at.setDisplayFormat("yyyy-MM-dd HH:mm:ss")

        self.custodian = QLineEdit()
        self.custodian.setText(self.logged_in_user)

        form.addRow("Case ID:", self.case_id)
        form.addRow("Examiner:", self.examiner)
        form.addRow("Evidence ID:", self.evidence_id)
        form.addRow("Evidence Type:", self.evidence_type)
        form.addRow("Description:", self.description)
        form.addRow("Received From:", self.received_from)
        form.addRow("Received At:", self.received_at)
        form.addRow("Custodian:", self.custodian)
        form.addRow("Storage Location:", self.storage_location)
        form.addRow("Notes:", self.notes)

        # --- buttons ---
        btns = QHBoxLayout()
        self.btn_save = QPushButton("Save & Continue")
        self.btn_cancel = QPushButton("Cancel")
        btns.addStretch()
        btns.addWidget(self.btn_save)
        btns.addWidget(self.btn_cancel)

        main_layout.addLayout(form)
        main_layout.addLayout(btns)
        self.setLayout(main_layout)

        # --- connections ---
        self.btn_save.clicked.connect(self.on_save)
        self.btn_cancel.clicked.connect(self.reject)

        # --- preload old data ---
        init_coc_db()
        data = get_coc_record()
        if data:
            self.case_id.setText(data.get("case_id", ""))
            self.examiner.setText(data.get("examiner", ""))
            self.evidence_id.setText(data.get("evidence_id", ""))
            idx = self.evidence_type.findText(data.get("evidence_type", "Other"))
            if idx != -1:
                self.evidence_type.setCurrentIndex(idx)
            self.description.setText(data.get("description", ""))
            self.received_from.setText(data.get("received_from", ""))
            self.custodian.setText(data.get("custodian", self.logged_in_user))
            self.storage_location.setText(data.get("storage_location", ""))
            self.notes.setPlainText(data.get("notes", ""))

        self.saved_data = None

    def on_save(self):
        if not self.case_id.text().strip() or not self.examiner.text().strip():
            QMessageBox.warning(self, "Missing", "Case ID and Examiner are required.")
            return
        self.saved_data = {
            "case_id": self.case_id.text().strip(),
            "examiner": self.examiner.text().strip(),
            "evidence_id": self.evidence_id.text().strip(),
            "evidence_type": self.evidence_type.currentText(),
            "description": self.description.text().strip(),
            "received_from": self.received_from.text().strip(),
            "received_at": self.received_at.dateTime().toString("yyyy-MM-dd HH:mm:ss"),
            "custodian": self.custodian.text().strip() or self.logged_in_user,
            "storage_location": self.storage_location.text().strip(),
            "hash_value": "",  # will be filled after acquisition
            "notes": self.notes.toPlainText().strip()
        }
        save_coc_record(self.saved_data)
        self.accept()


# -------------------------------------------------------------------
# ORIGINAL FUNCTIONS (from AUTH_FIXED, kept)
# -------------------------------------------------------------------

def analyze_key_findings(logs_text):
    import re
    findings = []

    # Suspicious processes or tools
    suspicious_keywords = [
        "mimikatz", "meterpreter", "nc.exe", "powershell.exe",
        "cmd.exe", "taskmgr.exe", "lsass", "winlogon", "dump"
    ]
    matched = [kw for kw in suspicious_keywords if kw.lower() in logs_text.lower()]
    if matched:
        findings.append(f"Suspicious tools or processes detected: {', '.join(set(matched))}")

    # Malfind plugin
    if "malfind" in logs_text.lower() and "Process:" in logs_text:
        findings.append("Potential injected code or suspicious processes found in memory (malfind).")

    # Network activity
    if "netscan" in logs_text.lower():
        if "LISTENING" in logs_text or "ESTABLISHED" in logs_text:
            findings.append("Active or suspicious network connections detected (netscan).")
        ips = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', logs_text)
        if ips:
            findings.append(f"IP addresses found: {', '.join(sorted(set(ips))[:10])}")

    # PowerShell or command use
    if "cmdline" in logs_text.lower():
        if "powershell" in logs_text.lower() or "cmd.exe" in logs_text.lower():
            findings.append("Command-line or PowerShell activity detected.")

    # Unsigned or hidden drivers
    if "driverscan" in logs_text.lower():
        if "Unsigned" in logs_text:
            findings.append("Unsigned drivers detected — possible tampering or hidden driver.")

    # Stopped services
    if "svcscan" in logs_text.lower() and "stopped" in logs_text.lower():
        findings.append("Some Windows services appear to be stopped or disabled unexpectedly.")

    # Processes overview
    suspicious_procs = re.findall(r'(\b\w+\.exe\b)', logs_text, re.IGNORECASE)
    if suspicious_procs:
        unique_procs = sorted(set(suspicious_procs))
        findings.append(f"Processes observed ({len(unique_procs)} total): {', '.join(unique_procs[:15])}")

    if not findings:
        findings.append("No significant anomalies detected from automated analysis.")

    return "\n".join(f"- {f}" for f in findings)


def generate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        return f"Error generating hash: {e}"


def generate_summary_report(selected_path, logs_text):
    logs_dir = os.path.join("C:/Users/Pacio/SOP_Toolkit_Project", "logs")
    os.makedirs(logs_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hash_value = generate_file_hash(selected_path)

    report_lines = [
        "SOP Toolkit Summary Report",
        f"Generated on: {timestamp}",
        f"Selected Path: {selected_path}",
        f"SHA-256 Hash: {hash_value}",
        "",
        "--- Analysis Summary ---",
        logs_text,
        "",
        "End of Report"
    ]

    report_path = os.path.join(logs_dir, "summary_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    return report_path


def generate_html_report(selected_path, logs_text, examiner_name, case_id, notes, coc_data=None):
    """
    Keep existing layout (headers/paragraphs) but prepend a CoC table at the top.
    """
    logs_dir = os.path.join("C:/Users/Pacio/SOP_Toolkit_Project", "reports")
    os.makedirs(logs_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hash_value = generate_file_hash(selected_path)

    # Update hash into coc_data (and DB already updated elsewhere)
    if coc_data is not None:
        coc_data = dict(coc_data)  # copy to avoid side-effects
        coc_data["hash_value"] = hash_value

    def esc(s):
        return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

    # CoC table to be PREPENDED, as requested
    coc_html = ""
    if coc_data:
        coc_html = f"""
        <h2>Chain of Custody</h2>
        <table border="1" cellpadding="6" cellspacing="0">
            <tr><td><b>Case ID</b></td><td>{esc(coc_data.get('case_id',''))}</td></tr>
            <tr><td><b>Examiner</b></td><td>{esc(coc_data.get('examiner',''))}</td></tr>
            <tr><td><b>Evidence ID</b></td><td>{esc(coc_data.get('evidence_id',''))}</td></tr>
            <tr><td><b>Evidence Type</b></td><td>{esc(coc_data.get('evidence_type',''))}</td></tr>
            <tr><td><b>Description</b></td><td>{esc(coc_data.get('description',''))}</td></tr>
            <tr><td><b>Received From</b></td><td>{esc(coc_data.get('received_from',''))}</td></tr>
            <tr><td><b>Received At</b></td><td>{esc(coc_data.get('received_at',''))}</td></tr>
            <tr><td><b>Storage Location</b></td><td>{esc(coc_data.get('storage_location',''))}</td></tr>
            <tr><td><b>Custodian</b></td><td>{esc(coc_data.get('custodian',''))}</td></tr>
            <tr><td><b>Hash (SHA-256)</b></td><td>{esc(coc_data.get('hash_value',''))}</td></tr>
            <tr><td><b>Notes</b></td><td>{esc(coc_data.get('notes',''))}</td></tr>
        </table>
        """

    html_content = f"""
    <html>
    <head><title>SOP Toolkit Report</title></head>
    <body>
        <h1>SOP Toolkit Summary Report</h1>
        <p><strong>Generated on:</strong> {timestamp}</p>
        <p><strong>Examiner:</strong> {examiner_name}</p>
        <p><strong>Case ID:</strong> {case_id}</p>
        <p><strong>Selected Path:</strong> {selected_path}</p>
        <p><strong>SHA-256 Hash:</strong> {hash_value}</p>
        {coc_html}
        <h2>Chain of Custody</h2>
        <p>{notes}</p>
        <h2>Automated Key Findings</h2>
        <pre>{analyze_key_findings(logs_text)}</pre>
        <h2>Full Analysis Summary</h2>
        <pre>{logs_text}</pre>
    </body>
    </html>
    """

    safe_timestamp = timestamp.replace(":", "-")
    report_path = os.path.join(logs_dir, f"report_{case_id}_{safe_timestamp}.html")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return report_path


class AcquisitionApp(QMainWindow):
    def __init__(self, coc_data: dict):
        super().__init__()
        uic.loadUi("acquisition_window_updated.ui", self)

        # Store CoC data locally
        self.coc_data = coc_data or {}

        # Connect buttons
        self.btnSOP.clicked.connect(self.show_sop)
        self.btnAbout.clicked.connect(self.show_about)
        self.btnBrowse.clicked.connect(self.browse_path)
        self.btnStart.clicked.connect(self.start_acquisition)

        # Initialize progress
        self.progress_value = 0
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_progress)

        # Paths to executables
        self.dumpit_path = "C:/Users/Pacio/SOP_Toolkit_Project/tools/DumpIt.exe"
        self.volatility_path = "C:/Users/Pacio/SOP_Toolkit_Project/volatility3/vol.py"

        # Auto-fill main window fields from CoC and lock them
        if hasattr(self, "txtExaminerName"):
            self.txtExaminerName.setText(self.coc_data.get("examiner",""))
            self.txtExaminerName.setReadOnly(True)
        if hasattr(self, "txtCaseID"):
            self.txtCaseID.setText(self.coc_data.get("case_id",""))
            self.txtCaseID.setReadOnly(True)
        if hasattr(self, "txtNotes"):
            self.txtNotes.setPlainText(self.coc_data.get("notes",""))
            self.txtNotes.setReadOnly(True)

    def show_sop(self):
        sop_text = """
Standard Operating Procedure (SOP)
----------------------------------
1. Preparation Phase
•   Ensure legal authorization for forensic investigation.
•   Prepare a forensic workstation with required tools: Python 3.x, Volatility 3, FTK Imager CLI or DumpIt, Tkinter or PyQt.
•   Document system metadata: hostname, IP address, OS version, and current time.
•   Ensure write-blocked external storage is available for saving memory dumps.
2. Memory Acquisition
•   Launch memory acquisition tool (FTK Imager CLI or DumpIt) via the toolkit GUI.
•   Save the memory dump to a secure, write-protected location.
•   Log acquisition details, including timestamp, tool used, and operator ID.
3. Hashing and Integrity Verification
•   Generate MD5 and SHA256 hashes of the memory dump using Python's hashlib.
•   Store hash values in a log file for integrity verification.
•   Display hash values in the GUI for user confirmation.
4. Memory Analysis
•   Select Volatility plugins to run (e.g., pslist, pstree, netscan, dlllist, cmdline, malfind).
•   Execute selected plugins via subprocess calls from the toolkit.
•   Parse plugin outputs and store results in a structured format (CSV or JSON).
5. Artifact Classification
•   Apply rule-based or ML-based classification to categorize artifacts (e.g., credentials, malware traces, network activity).
•   Tag and organize artifacts for reporting and further analysis.
6. Logging and Chain-of-Custody
•   Log all actions performed by the toolkit, including timestamps, tool versions, and user inputs.
•   Maintain a chain-of-custody record for each memory dump and analysis session.
7. Report Generation
•   Compile analysis results, hash values, system metadata, and artifact summaries into a structured report.
•   Generate PDF or HTML report using Python libraries (e.g., reportlab or pdfkit).
•   Save and optionally export the report to external storage.

"""
        dlg = TextPopup("SOP Guidelines", sop_text, self)
        dlg.exec_()

    def show_about(self):
        about_text = """
About
-----
SOP Toolkit with integrated Authentication and Chain of Custody.
This tool supports memory acquisition, Volatility analysis, and report generation,
and captures Chain of Custody details for evidentiary integrity.
"""
        dlg = TextPopup("About", about_text, self)
        dlg.exec_()

    def browse_path(self):
        file, _ = QFileDialog.getOpenFileName(self, "Select Memory Dump or Folder", "", "Raw Files (*.raw *.img *.vmem *.dmp *.dump *.lime *.elf);;All Files (*)")
        if file:
            self.txtPath.setText(file)
        else:
            folder = QFileDialog.getExistingDirectory(self, "Select Folder")
            if folder:
                self.txtPath.setText(folder)

    def update_progress(self):
        self.progress_value += 5
        if self.progress_value <= 100:
            self.progressBar.setValue(self.progress_value)
        else:
            self.timer.stop()

    def start_acquisition(self):
        selected_path = self.txtPath.text()
        if not selected_path:
            QMessageBox.warning(self, "Warning", "Please select a file or folder first!")
            return

        # If file, analyze directly
        if os.path.isfile(selected_path) and selected_path.lower().endswith(('.raw', '.img', '.vmem', '.dmp', '.dump', '.lime', '.elf')):
            self.txtLogs.append("Analyzing existing memory image...")
            self.analyze_memory_image(selected_path)

        # If folder, attempt DumpIt
        elif os.path.isdir(selected_path):
            self.txtLogs.append("Starting memory acquisition using DumpIt...")
            if not os.path.exists(self.dumpit_path):
                self.txtLogs.append(f"DumpIt not found at '{self.dumpit_path}'. Please update the path in the script.")
                return
            try:
                proc = subprocess.run([self.dumpit_path], cwd=selected_path, capture_output=True, text=True)
                self.txtLogs.append("DumpIt stdout:")
                self.txtLogs.append(proc.stdout or "<no stdout>")
                if proc.returncode != 0:
                    self.txtLogs.append(f"DumpIt returned exit code {proc.returncode}. stderr:")
                    self.txtLogs.append(proc.stderr or "<no stderr>")
                raw_files = [f for f in os.listdir(selected_path) if f.lower().endswith(('.raw', '.dmp', '.img'))]
                if not raw_files:
                    self.txtLogs.append("No .raw file found after DumpIt execution.")
                    return
                raw_files.sort(key=lambda x: os.path.getmtime(os.path.join(selected_path, x)), reverse=True)
                dump_output_path = os.path.join(selected_path, raw_files[0])
                self.txtLogs.append(f"Using memory image: {dump_output_path}")
                self.analyze_memory_image(dump_output_path)
                self.txtLogs.append("DumpIt executed and analysis started.")
            except Exception as e:
                self.txtLogs.append(f"Error running DumpIt: {e}")
                return
        else:
            QMessageBox.warning(self, "Invalid Selection", "Please select a valid folder or evidence image file.")
            return

        # After analysis: compute hash and update CoC DB
        try:
            hash_value = generate_file_hash(selected_path)
            self.coc_data["hash_value"] = hash_value
            update_coc_hash(hash_value)
        except Exception as e:
            self.txtLogs.append(f"Error computing hash: {e}")

        # Generate reports (summary unchanged, HTML with CoC table)
        logs_text = self.txtLogs.toPlainText()
        generate_summary_report(selected_path, logs_text)
        key_findings = analyze_key_findings(logs_text)
        generate_html_report(
            selected_path,
            logs_text + '\\n\\n--- Automated Key Findings ---\\n' + key_findings,
            self.txtExaminerName.text(),
            self.txtCaseID.text(),
            self.txtNotes.toPlainText(),
            coc_data=self.coc_data
        )

        # Progress bar animation
        self.progress_value = 0
        self.progressBar.setValue(0)
        self.timer.start(500)

    def analyze_memory_image(self, image_path):
        plugins = [
            "windows.info",
            "windows.pslist",
            "windows.pstree",
            "windows.cmdline",
            "windows.netscan",
            "windows.malfind",
            "windows.svcscan",
            "windows.driverscan",
            "windows.modules"
        ]

        self.txtLogs.append("Starting analysis using Volatility...")

        if not os.path.isfile(image_path):
            self.txtLogs.append(f"Image file does not exist: {image_path}")
            return

        python_exec = sys.executable
        candidates = [
            [python_exec, self.volatility_path, "-f", image_path],
            [python_exec, "-m", "volatility3", "-f", image_path]
        ]

        for plugin in plugins:
            for cmd in candidates:
                full_cmd = cmd + [plugin]
                try:
                    self.txtLogs.append(f"Running: {' '.join(full_cmd)}")
                    result = subprocess.run(full_cmd, capture_output=True, text=True, check=True)
                    plugin_output = f"\\n\\n--- {plugin} ---\\n{result.stdout}"
                    self.txtLogs.append(plugin_output)
                    break
                except subprocess.CalledProcessError as e:
                    self.txtLogs.append(f"Error running {plugin}: {e}")
                    continue
                except Exception as ex:
                    self.txtLogs.append(f"Unexpected error with {plugin}: {ex}")
                    continue

        self.txtLogs.append("Volatility analysis completed successfully.")


class TextPopup(QDialog):
    def __init__(self, title, text, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(800, 600)

        layout = QVBoxLayout()

        label = QLabel(title)
        layout.addWidget(label)

        text_box = QTextEdit()
        text_box.setReadOnly(True)
        text_box.setText(text)
        layout.addWidget(text_box)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        layout.addWidget(close_btn)

        self.setLayout(layout)


# -------------------------------------------------------------------
# MAIN (login -> optional admin panel -> COC popup -> main window)
# -------------------------------------------------------------------

if __name__ == "__main__":
    try:
        init_user_db()  # ensure users.db exists + default admin
        init_coc_db()   # ensure CoC DB exists

        app = QApplication(sys.argv)

        # 1) Login dialog
        login = LoginDialog()
        if login.exec_() != QDialog.Accepted or not login.logged_in_user:
            sys.exit(0)

        username, role = login.logged_in_user

        # 2) If admin logged in, show Admin Panel first (as before)
        if role == "admin":
            panel = AdminPanel()
            panel.exec_()
            # Ask whether to open the main app
            if QMessageBox.question(None, "Continue",
                                    "Open the forensic application window now?",
                                    QMessageBox.Yes | QMessageBox.No,
                                    QMessageBox.Yes) != QMessageBox.Yes:
                sys.exit(0)

        # 3) ALWAYS show CoC popup after any login (as requested)
        coc = CoCDialog(logged_in_user=username)
        if coc.exec_() != QDialog.Accepted or not coc.saved_data:
            # Cancel -> exit cleanly
            sys.exit(0)
        coc_data = coc.saved_data  # dict with CoC info

        # 4) Launch forensic GUI with CoC data (fields auto-filled & locked)
        window = AcquisitionApp(coc_data=coc_data)
        window.show()
        sys.exit(app.exec_())

    except Exception as e:
        import traceback
        print("[!] Error launching application:")
        traceback.print_exc()
        try:
            input("Press Enter to exit...")
        except Exception:
            pass
