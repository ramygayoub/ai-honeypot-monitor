"""
AI-Powered Honeypot Attack Classifier (Gemini version, hybrid rule-based + LLM)
---------------------------------------------------------
Obvious cases (scan-only, no login) are classified locally for free.
Only genuinely interesting sessions (successful login + commands) go to Gemini.
"""

import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from google import genai
from google.genai import errors as genai_errors

COWRIE_LOG_PATH = os.environ.get("COWRIE_LOG_PATH", "/home/ramyayoub/cowrie/var/log/cowrie/cowrie.json")
DB_PATH = os.environ.get("HONEYPOT_DB_PATH", str(Path(__file__).parent / "honeypot.db"))
POLL_INTERVAL_SECONDS = 30
GEMINI_MODEL = "gemini-3.1-flash-lite"
SECONDS_BETWEEN_CALLS = 4

CLASSIFICATION_PROMPT = """You are a security analyst reviewing a honeypot session log. \
Based on the sequence of events below (connection info, login attempts, and any \
commands typed), classify the attacker's likely behavior.

Respond with ONLY a JSON object, no other text, in this exact format:
{{
  "attack_type": "one of: port_scan, credential_stuffing, brute_force, exploit_attempt, \
recon, malware_download, botnet_recruitment, unknown",
  "confidence": "high|medium|low",
  "summary": "one sentence plain-English summary of what the attacker was trying to do",
  "notable_commands": ["list", "of", "any", "suspicious", "commands", "typed"]
}}

Session events:
{events}
"""


def init_db(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS classified_sessions (
            session_id TEXT PRIMARY KEY,
            src_ip TEXT,
            start_time TEXT,
            end_time TEXT,
            event_count INTEGER,
            attack_type TEXT,
            confidence TEXT,
            summary TEXT,
            notable_commands TEXT,
            raw_events TEXT,
            classified_at TEXT,
            classified_by TEXT
        )
        """
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS processed_offsets (log_path TEXT PRIMARY KEY, byte_offset INTEGER)"
    )
    # Add the column if the table already existed from a previous run
    try:
        conn.execute("ALTER TABLE classified_sessions ADD COLUMN classified_by TEXT")
    except sqlite3.OperationalError:
        pass
    conn.commit()


def load_offset(conn, log_path):
    row = conn.execute(
        "SELECT byte_offset FROM processed_offsets WHERE log_path = ?", (log_path,)
    ).fetchone()
    return row[0] if row else 0


def save_offset(conn, log_path, offset):
    conn.execute(
        "INSERT INTO processed_offsets (log_path, byte_offset) VALUES (?, ?) "
        "ON CONFLICT(log_path) DO UPDATE SET byte_offset = excluded.byte_offset",
        (log_path, offset),
    )
    conn.commit()


def read_new_events(log_path, offset):
    events = []
    if not os.path.exists(log_path):
        return events, offset

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(offset)
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        new_offset = f.tell()
    return events, new_offset


def group_by_session(events):
    sessions = {}
    for event in events:
        session_id = event.get("session")
        if not session_id:
            continue
        sessions.setdefault(session_id, []).append(event)
    return sessions


_recon_counter = {"count": 0}

def rule_based_classify(events):
    """Classify obvious cases locally, for free. Returns None if it needs the LLM."""
    event_ids = [e.get("eventid", "") for e in events]

    has_login_success = "cowrie.login.success" in event_ids
    has_login_failed = "cowrie.login.failed" in event_ids
    has_commands = "cowrie.command.input" in event_ids

    # Successful login + ran commands: sample only 1 in 5 for real LLM analysis,
    # rule-classify the rest as recon (this pattern is overwhelmingly generic
    # fingerprinting scripts based on prior data).
    if has_login_success and has_commands:
        _recon_counter["count"] += 1
        if _recon_counter["count"] % 5 == 0:
            return None  # send this one to the LLM
        return {
            "attack_type": "recon",
            "confidence": "medium",
            "summary": "Successful login followed by command execution, consistent with automated system fingerprinting (rule-based, sampled).",
            "notable_commands": [],
        }

    # No login attempt at all, very few events = simple scan/banner grab
    if not has_login_success and not has_login_failed:
        return {
            "attack_type": "port_scan",
            "confidence": "medium",
            "summary": "Connection with no login attempt — automated scan or banner grab (rule-based).",
            "notable_commands": [],
        }

    # Login attempted (failed) but never succeeded = brute force probe
    if has_login_failed and not has_login_success:
        return {
            "attack_type": "brute_force",
            "confidence": "medium",
            "summary": "Failed login attempt(s), no successful authentication (rule-based).",
            "notable_commands": [],
        }

    # Logged in but ran no commands = low-value, still worth noting
    if has_login_success and not has_commands:
        return {
            "attack_type": "credential_stuffing",
            "confidence": "medium",
            "summary": "Successful login with no follow-up commands (rule-based).",
            "notable_commands": [],
        }

    return None  # fallback: let the LLM handle anything unexpected


def classify_session(client, session_id, events, retries=3):
    events_text = json.dumps(events, indent=2, default=str)[:6000]

    for attempt in range(retries):
        try:
            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=CLASSIFICATION_PROMPT.format(events=events_text),
                config={
                    "response_mime_type": "application/json",
                    "max_output_tokens": 2048,
                    "thinking_config": {"thinking_level": "minimal"},
                },
            )
            break
        except genai_errors.ClientError as e:
            if "PerDay" in str(e):
                print(f"    [DAILY QUOTA] Hit daily free-tier limit. Marking pending.")
                return {
                    "attack_type": "pending",
                    "confidence": "low",
                    "summary": "Daily API quota reached — will classify once quota resets.",
                    "notable_commands": [],
                }
            elif "RESOURCE_EXHAUSTED" in str(e) and attempt < retries - 1:
                print(f"    [RATE LIMIT] Waiting 60s before retry ({attempt + 1}/{retries})...")
                time.sleep(60)
                continue
            else:
                print(f"    [ERROR] Unhandled API error: {e}")
                return {
                    "attack_type": "unknown",
                    "confidence": "low",
                    "summary": f"API error: {str(e)[:200]}",
                    "notable_commands": [],
                }
    else:
        return {
            "attack_type": "unknown",
            "confidence": "low",
            "summary": "Rate limit exceeded after retries.",
            "notable_commands": [],
        }

    raw_text = response.text.strip() if response.text else ""

    if raw_text.startswith("```"):
        raw_text = raw_text.split("```")[1]
        if raw_text.startswith("json"):
            raw_text = raw_text[4:]
        raw_text = raw_text.strip()

    try:
        result = json.loads(raw_text)
    except json.JSONDecodeError:
        print(f"    [DEBUG] Could not parse response. Raw text was:\n{raw_text!r}")
        result = {
            "attack_type": "unknown",
            "confidence": "low",
            "summary": "Could not parse AI classification.",
            "notable_commands": [],
        }
    return result


def store_session(conn, session_id, events, classification, classified_by):
    src_ip = next((e.get("src_ip") for e in events if e.get("src_ip")), "unknown")
    timestamps = [e.get("timestamp") for e in events if e.get("timestamp")]
    start_time = min(timestamps) if timestamps else ""
    end_time = max(timestamps) if timestamps else ""

    conn.execute(
        """
        INSERT INTO classified_sessions
            (session_id, src_ip, start_time, end_time, event_count,
             attack_type, confidence, summary, notable_commands, raw_events, classified_at, classified_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(session_id) DO UPDATE SET
            attack_type = excluded.attack_type,
            confidence = excluded.confidence,
            summary = excluded.summary,
            notable_commands = excluded.notable_commands,
            classified_at = excluded.classified_at,
            classified_by = excluded.classified_by
        """,
        (
            session_id,
            src_ip,
            start_time,
            end_time,
            len(events),
            classification.get("attack_type", "unknown"),
            classification.get("confidence", "low"),
            classification.get("summary", ""),
            json.dumps(classification.get("notable_commands", [])),
            json.dumps(events, default=str),
            datetime.now(timezone.utc).isoformat(),
            classified_by,
        ),
    )
    conn.commit()


def main():
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise SystemExit(
            "Set GEMINI_API_KEY environment variable before running.\n"
            "Get a free key at https://aistudio.google.com/apikey"
        )

    client = genai.Client(api_key=api_key)
    conn = sqlite3.connect(DB_PATH)
    init_db(conn)

    print(f"Watching {COWRIE_LOG_PATH} — polling every {POLL_INTERVAL_SECONDS}s. Ctrl+C to stop.")

    while True:
        offset = load_offset(conn, COWRIE_LOG_PATH)
        events, new_offset = read_new_events(COWRIE_LOG_PATH, offset)

        if events:
            sessions = group_by_session(events)
            print(f"[{datetime.now().isoformat()}] {len(sessions)} session(s) with new activity")
            for session_id, session_events in sessions.items():
                try:
                    rule_result = rule_based_classify(session_events)
                    if rule_result is not None:
                        store_session(conn, session_id, session_events, rule_result, "rule-based")
                        print(f"  -> {session_id}: {rule_result['attack_type']} (rule-based, no API call)")
                    else:
                        classification = classify_session(client, session_id, session_events)
                        store_session(conn, session_id, session_events, classification, "gemini")
                        print(f"  -> {session_id}: {classification.get('attack_type')} "
                              f"({classification.get('confidence')}) — {classification.get('summary')}")
                        time.sleep(SECONDS_BETWEEN_CALLS)
                except Exception as e:
                    print(f"    [UNEXPECTED ERROR] Skipping session {session_id}: {e}")

            save_offset(conn, COWRIE_LOG_PATH, new_offset)

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
