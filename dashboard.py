import os
import streamlit as st
import plotly.express as px
from detect import (
    parse_text, brute_force, incidents, invalid_users,
    suspicious_success, ml_anomalies, geolocate
)
from ips import build_blocklist, to_iptables, to_nft, to_ufw

st.set_page_config(page_title="Log Anomaly Dashboard", layout="wide")
st.title("Log Anomaly Dashboard")


@st.cache_data(show_spinner="Locating attacker IPs...")
def cached_geolocate(ips):
    return geolocate(list(ips))


# ---- Sidebar ----
uploaded = st.sidebar.file_uploader("Upload a log file", type=["log", "txt"])
threshold = st.sidebar.slider("Brute force threshold (failures/min)", 3, 30, 5)
min_users = st.sidebar.slider("Invalid users threshold (distinct names)", 2, 20, 3)
year = st.sidebar.number_input("Year (for logs without a year)", 2000, 2030, 2015)
allow_text = st.sidebar.text_area(
    "IPS allowlist (one IP or CIDR per line)",
    help="Addresses listed here are never recommended for blocking.",
)
allowlist = [x.strip() for x in allow_text.splitlines() if x.strip()]

if uploaded is not None:
    text = uploaded.getvalue().decode("utf-8", errors="ignore")
    st.sidebar.success(f"Using: {uploaded.name}")
elif os.path.exists("data/sample.log"):
    with open("data/sample.log") as f:
        text = f.read()
    st.sidebar.info("Using sample data/sample.log")
else:
    st.warning("Upload a log file from the sidebar to start.")
    st.stop()

df = parse_text(text, int(year))

if df.empty:
    st.error("No matching log lines found. Check the log format.")
    st.stop()

# ---- Detection ----
alerts = brute_force(df, threshold)
inc = incidents(alerts)
inv = invalid_users(df, min_users)
success = suspicious_success(df, threshold)
ml = ml_anomalies(df)
blocklist = build_blocklist(df, allowlist, min_users=min_users)

# ---- Metrics ----
c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("Total events", len(df))
c2.metric("Failed logins", int((df["status"] == "Failed").sum()))
c3.metric("Attack incidents", len(inc))
c4.metric("User-guessing IPs", len(inv))
c5.metric("Suspicious successes", len(success))
c6.metric("IPs to block", int((blocklist["action"] == "block").sum()))

# ---- Attack map ----
st.subheader("Attack sources by location")
failed_counts = df[df["status"] == "Failed"]["ip"].value_counts().reset_index()
failed_counts.columns = ["ip", "failed_logins"]
geo = cached_geolocate(tuple(failed_counts["ip"].tolist()))

if geo.empty:
    st.info("No public IPs to locate in this log (local addresses have no map position).")
else:
    geo = geo.merge(failed_counts, on="ip")
    fig_map = px.scatter_geo(
        geo, lat="lat", lon="lon", size="failed_logins",
        hover_name="ip", hover_data=["country", "city", "failed_logins"],
        projection="natural earth", title="Failed logins by source",
        height=450,
    )
    st.plotly_chart(fig_map, width="stretch")

    by_country = (
        geo.groupby("country")["failed_logins"].sum()
        .reset_index().sort_values("failed_logins", ascending=False)
    )
    st.dataframe(by_country, width="stretch")

# ---- Charts ----
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

# ---- Tables ----
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

# ---- IPS recommendations ----
st.subheader("IPS recommendations (dry-run: nothing is blocked)")
st.dataframe(blocklist, width="stretch")
st.caption(
    "Recommendations only. Private addresses and the allowlist are never "
    "blocked. Review before applying on a host you control."
)

d1, d2, d3 = st.columns(3)
d1.download_button(
    "Download iptables rules",
    "\n".join(to_iptables(blocklist)) or "# nothing to block",
    file_name="block_iptables.sh",
)
d2.download_button(
    "Download nftables rules",
    "\n".join(to_nft(blocklist)) or "# nothing to block",
    file_name="block_nft.sh",
)
d3.download_button(
    "Download ufw rules",
    "\n".join(to_ufw(blocklist)) or "# nothing to block",
    file_name="block_ufw.sh",
)