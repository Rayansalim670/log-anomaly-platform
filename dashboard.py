import streamlit as st
import plotly.express as px
from detect import (
    parse_text, brute_force, incidents, invalid_users,
    suspicious_success, ml_anomalies
)

st.set_page_config(page_title="Log Anomaly Dashboard", layout="wide")
st.title("Log Anomaly Dashboard")

uploaded = st.sidebar.file_uploader("Upload a log file", type=["log", "txt"])
threshold = st.sidebar.slider("Brute force threshold (failures/min)", 3, 30, 5)
min_users = st.sidebar.slider("Invalid users threshold (distinct names)", 2, 20, 3)
year = st.sidebar.number_input("Year (for logs without a year)", 2000, 2030, 2015)

if uploaded is not None:
    text = uploaded.getvalue().decode("utf-8", errors="ignore")
    st.sidebar.success(f"Using: {uploaded.name}")
else:
    with open("data/auth.log") as f:
        text = f.read()
    st.sidebar.info("Using sample data/auth.log")

df = parse_text(text, int(year))

if df.empty:
    st.error("No matching log lines found. Check the log format.")
    st.stop()

alerts = brute_force(df, threshold)
inc = incidents(alerts)
inv = invalid_users(df, min_users)
success = suspicious_success(df, threshold)
ml = ml_anomalies(df)

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total events", len(df))
c2.metric("Failed logins", int((df["status"] == "Failed").sum()))
c3.metric("Attack incidents", len(inc))
c4.metric("User-guessing IPs", len(inv))
c5.metric("Suspicious successes", len(success))

timeline = df.set_index("time").resample("5min")["status"].count().reset_index()
timeline.columns = ["Time", "Events"]
fig = px.line(timeline, x="Time", y="Events", title="Events over time")
if not alerts.empty:
    for t in alerts["time"]:
        fig.add_vline(x=t, line_dash="dash", line_color="red", opacity=0.3)
st.plotly_chart(fig, width="stretch")

left, right = st.columns(2)
with left:
    top = df[df["status"] == "Failed"]["ip"].value_counts().head(10).reset_index()
    top.columns = ["IP", "Failed logins"]
    st.plotly_chart(
        px.bar(top, x="IP", y="Failed logins", title="Top IPs by failed logins"),
        width="stretch",
    )
with right:
    by_status = df["status"].value_counts().reset_index()
    by_status.columns = ["Status", "Count"]
    st.plotly_chart(
        px.pie(by_status, names="Status", values="Count",
               title="Accepted vs Failed", hole=0.4),
        width="stretch",
    )

st.subheader("Attack incidents (grouped)")
st.dataframe(inc, width="stretch")

st.subheader("Username guessing (invalid users)")
st.dataframe(inv, width="stretch")

st.subheader("Brute force alerts (per minute)")
st.dataframe(alerts, width="stretch")

st.subheader("Suspicious successful logins")
st.dataframe(success, width="stretch")

st.subheader("ML anomalies (Isolation Forest)")
st.dataframe(ml, width="stretch")