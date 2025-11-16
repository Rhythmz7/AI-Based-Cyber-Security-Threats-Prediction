# pages/2_IP_Scanner.py
import streamlit as st
import re
import random
from datetime import datetime

# (Copied from threat_dashboard.py)
def validate_ip(ip):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(part) <= 255 for part in parts)

st.title("🌐 IP Address Security Scanner")
ip = st.text_input("Enter IP Address:", "8.8.8.8")

if st.button("Scan IP"):
    if not validate_ip(ip):
        st.error("Invalid IP address format!")
    else:
        with st.spinner(f"Scanning IP Address: {ip}..."):
            # Simulate scanning
            ip_parts = [int(x) for x in ip.split('.')]
            risk_score = sum(ip_parts) % 100
            
            if risk_score < 30: risk_level = "🟢 SAFE"
            elif risk_score < 60: risk_level = "🟡 MODERATE"
            elif risk_score < 80: risk_level = "🟠 RISKY"
            else: risk_level = "🔴 CRITICAL"

            st.subheader("📊 SECURITY ANALYSIS REPORT")
            st.metric("Risk Level", risk_level, f"{risk_score} / 100 Score")
            
            st.write(f"**IP Address:** {ip}")
            st.write(f"**Scan Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            # (You can port the rest of the checks: Geo, Blacklist, etc.
            # from the 'perform_scan' function in threat_dashboard.py)
            st.subheader("🔒 SECURITY CHEKS")
            st.write(f"**Blacklist Status:** {'✅ Not Listed' if risk_score < 60 else '❌ Listed'}")
            st.write(f"**Malware History:** {'✅ Clean' if risk_score < 40 else '⚠️ Suspicious'}")
            st.write(f"**DDoS Activity:** {'✅ No' if risk_score < 70 else '❌ Detected'}")