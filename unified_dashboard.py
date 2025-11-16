# unified_dashboard.py
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from db_manager import Database
from datetime import datetime, timedelta
import os
import psutil

try:
    import google.generativeai as genai
except Exception:
    genai = None

# --- Page Config ---
st.set_page_config(
    page_title="Unified SIEM Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# --- Database Connection ---
@st.cache_resource
def get_db():
    # Reads credentials from Streamlit's secrets
    return Database(
        db_type="postgres",
        host=st.secrets["db_host"],
        port=st.secrets["db_port"],
        database=st.secrets["db_name"],
        user=st.secrets["db_user"],
        password=st.secrets["db_pass"]
    )
db = get_db()

# --- Gemini Config (from app.py) ---
@st.cache_resource
def init_gemini():
    if genai is None:
        return None, False
    
    # Try secrets first, then env
    api_key = None
    try:
        api_key = st.secrets["GEMINI_API_KEY"]
    except Exception:
        api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    
    if not api_key:
        return None, False
        
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-2.5-flash-lite") # Or your preferred model
        return model, True
    except Exception:
        return None, False

gemini_model, gemini_available = init_gemini()
# --- End of Gemini Config ---

@st.cache_data(ttl=30)  # Cache for 30 seconds
def get_network_status():
    """Gets the active network connection type and name."""
    try:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()

        for iface, iface_stats in stats.items():
            # Check if interface is up, not loopback, and has an IP
            if iface_stats.isup and 'lo' not in iface.lower() and iface in addrs:
                # Check for a valid IPv4 address
                for addr in addrs[iface]:
                    if addr.family == 2:  # 2 is AF_INET (IPv4)
                        # Guess type based on name
                        if 'eth' in iface.lower() or 'ethernet' in iface.lower():
                            return "Ethernet", f"🌐 {iface}"
                        elif 'wi-fi' in iface.lower() or 'wlan' in iface.lower():
                            return "Wi-Fi", f"📶 {iface}"
                        
                        # Generic "connected" if name doesn't match
                        return "Connected", f"🌐 {iface}"
        
        return "Offline", "❌ Not Connected"
    except Exception:
        return "Unknown", "❓ Status Unknown"

# --- Helper Functions ---
@st.cache_data(ttl=5) # Cache data for 5 seconds
def fetch_dashboard_data():
    logs = db.query("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 1000")
    alerts = db.query("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 100")
    
    logs_df = pd.DataFrame(logs)
    alerts_df = pd.DataFrame(alerts)
    
    # Get KPI data
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=1)
    
    total_attacks = db.query(f"SELECT COUNT(*) as count FROM logs WHERE timestamp >= '{start_time.isoformat()}'")[0]['count']
    critical_threats = db.query(f"SELECT COUNT(*) as count FROM alerts WHERE severity >= 4 AND timestamp >= '{start_time.isoformat()}'")[0]['count']
    
    # Simulate blocked
    blocked_count = int(total_attacks * 0.78) # Simulate 78% block rate
    
    # Get chart data
    attack_counts = db.query("SELECT threat_type, COUNT(*) as count FROM logs GROUP BY threat_type ORDER BY count DESC LIMIT 10")
    severity_counts = db.query("SELECT severity, COUNT(*) as count FROM logs GROUP BY severity")
    
    # Time series data (last 100 events)
    time_series = db.query("SELECT timestamp, severity FROM logs ORDER BY timestamp DESC LIMIT 100")
    time_series_df = pd.DataFrame(time_series)
    if not time_series_df.empty:
        time_series_df['timestamp'] = pd.to_datetime(time_series_df['timestamp'])
        time_series_df = time_series_df.set_index('timestamp').resample('1min').count()
    
    return {
        "logs_df": logs_df,
        "alerts_df": alerts_df,
        "kpis": {
            "total": total_attacks,
            "blocked": blocked_count,
            "critical": critical_threats
        },
        "charts": {
            "attacks": pd.DataFrame(attack_counts),
            "severity": pd.DataFrame(severity_counts),
            "time_series": time_series_df
        }
    }

# --- Main Dashboard UI ---
st.title("🛡️ Unified Cyber Threat Dashboard")
st.markdown("Real-time monitoring and AI-powered threat intelligence.")

# Auto-refreshing data
data = fetch_dashboard_data()

# --- KPI Cards ---
st.header("Hourly Security Summary")

# Get network status
net_type, net_name = get_network_status()

kpi_cols = st.columns(4)  # <-- Changed to 4
kpi_cols[0].metric("🔴 Total Attacks", data['kpis']['total'])
kpi_cols[1].metric("✅ Blocked", data['kpis']['blocked'])
kpi_cols[2].metric("⚠️ Critical Alerts", data['kpis']['critical'])
kpi_cols[3].metric(f"📡 Network ({net_type})", net_name) # <-- Added this card

st.divider()

# --- Charts ---
st.header("Live Threat Analysis")
chart_cols = st.columns(2)

with chart_cols[0]:
    # Top Attack Types
    if not data['charts']['attacks'].empty:
        fig_attacks = px.bar(
            data['charts']['attacks'],
            x="count",
            y="threat_type",
            orientation='h',
            title="Top 10 Attack Types"
        )
        st.plotly_chart(fig_attacks, use_container_width=True)
    else:
        st.info("No attack data for chart.")

with chart_cols[1]:
    # Severity Distribution
    if not data['charts']['severity'].empty:
        # Map severity numbers to names
        sev_map = {1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical'}
        df = data['charts']['severity'].copy()
        df['severity_name'] = df['severity'].map(sev_map)
        
        fig_severity = px.pie(
            df,
            names="severity_name",
            values="count",
            title="Threat Severity Distribution",
            hole=0.3
        )
        st.plotly_chart(fig_severity, use_container_width=True)
    else:
        st.info("No severity data for chart.")

# Time Series Chart
st.subheader("Attacks Over Time (per minute)")
if not data['charts']['time_series'].empty:
    fig_time = px.line(
        data['charts']['time_series'],
        y="severity", # 'severity' is now a count of events
        title="Incoming Threats"
    )
    st.plotly_chart(fig_time, use_container_width=True)
else:
    st.info("No time series data yet.")

st.divider()

# --- Live Feeds ---
st.header("Live Feeds")
feed_cols = st.columns(2)

with feed_cols[0]:
    st.subheader("🌍 Live Threat Feed")
    st.dataframe(
        data['logs_df'][['timestamp', 'threat_type', 'src_ip', 'dst_ip', 'protocol', 'severity']],
        use_container_width=True,
        height=400
    )

with feed_cols[1]:
    st.subheader("🚨 Live Alert Panel")
    st.dataframe(
        data['alerts_df'][['timestamp', 'threat_type', 'source_ip', 'severity', 'description']],
        use_container_width=True,
        height=400
    )

# --- Gemini Chatbot (from app.py) ---
st.divider()
st.header("🤖 AI Agent (Gemini)")
if not gemini_available:
    st.info("Gemini not configured. Set GEMINI_API_KEY in secrets or env.")
else:
    if "chat_messages" not in st.session_state:
        st.session_state.chat_messages = []

    for m in st.session_state.chat_messages:
        with st.chat_message(m["role"]):
            st.markdown(m["content"])

    if prompt := st.chat_input("Ask about cyber threats..."):
        st.session_state.chat_messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        with st.chat_message("assistant"):
            try:
                # Add context from the dashboard
                context = f"""
                You are a cybersecurity assistant. Here is a summary of the current dashboard:
                - Total Attacks (last hour): {data['kpis']['total']}
                - Critical Alerts (last hour): {data['kpis']['critical']}
                - Top Attack Type: {data['charts']['attacks'].iloc[0]['threat_type'] if not data['charts']['attacks'].empty else 'N/A'}
                
                Answer the user's question based on this context and your general knowledge.
                """
                full_prompt = f"{context}\n\nUser Question: {prompt}"
                
                res = gemini_model.generate_content(full_prompt)
                response = res.text
            except Exception as e:
                response = f"Gemini error: {e}"
            
            st.markdown(response)
            st.session_state.chat_messages.append({"role": "assistant", "content": response})

# --- Auto-refresh ---
st.write("This dashboard auto-refreshes every 5 seconds.")
import time
time.sleep(5)
st.rerun()