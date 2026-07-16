"""
Honeypot Attack Dashboard
--------------------------
Live view of AI-classified attack sessions from the honeypot.
"""

import json
import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st

DB_PATH = str(Path(__file__).parent / "honeypot.db")

st.set_page_config(page_title="Honeypot Attack Monitor", layout="wide")
st.title("🍯 AI-Classified Honeypot Attack Monitor")


@st.cache_data(ttl=30)
def load_data() -> pd.DataFrame:
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql_query(
            "SELECT * FROM classified_sessions ORDER BY start_time DESC", conn
        )
    except Exception:
        df = pd.DataFrame()
    conn.close()
    return df


df = load_data()

if df.empty:
    st.info("No classified sessions yet. Make sure classify_sessions.py is running "
             "and the honeypot has received traffic.")
    st.stop()

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Sessions", len(df))
col2.metric("Unique Source IPs", df["src_ip"].nunique())
col3.metric("High-Confidence Attacks", len(df[df["confidence"] == "high"]))
col4.metric("Exploit Attempts", len(df[df["attack_type"] == "exploit_attempt"]))

st.divider()

left, right = st.columns([1, 1])

with left:
    st.subheader("Attack Types")
    type_counts = df["attack_type"].value_counts()
    st.bar_chart(type_counts)

with right:
    st.subheader("Top Attacking IPs")
    ip_counts = df["src_ip"].value_counts().head(10)
    st.bar_chart(ip_counts)

st.divider()

st.subheader("Session Log")

attack_types = ["All"] + sorted(df["attack_type"].dropna().unique().tolist())
selected_type = st.selectbox("Filter by attack type", attack_types)

filtered = df if selected_type == "All" else df[df["attack_type"] == selected_type]

for _, row in filtered.head(50).iterrows():
    with st.expander(
        f"{row['start_time']} — {row['src_ip']} — **{row['attack_type']}** "
        f"({row['confidence']} confidence)"
    ):
        st.write(f"**Summary:** {row['summary']}")
        try:
            commands = json.loads(row["notable_commands"]) if row["notable_commands"] else []
        except (json.JSONDecodeError, TypeError):
            commands = []
        if commands:
            st.write("**Notable commands:**")
            for cmd in commands:
                st.code(cmd, language="bash")
        st.caption(f"Session ID: {row['session_id']} | Events: {row['event_count']}")
