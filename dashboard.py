import streamlit as st
import json
import os
import pandas as pd

# Page Config
st.set_page_config(page_title="Guardian-OT | Dashboard", layout="wide", page_icon="🛡️")

# Custom CSS for a high-signal look
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    .stMetric { background-color: #161b22; padding: 15px; border-radius: 10px; border: 1px solid #30363d; }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ Guardian-OT: Forensic Dashboard")
st.markdown("---")

# 1. Load Data
report_dir = "reports"
if not os.path.exists(report_dir):
    os.makedirs(report_dir)

reports = sorted([f for f in os.listdir(report_dir) if f.endswith(".json")], reverse=True)

if not reports:
    st.warning("⚠️ No forensic reports found in /reports. Run main.py first!")
else:
    # Sidebar Navigation
    st.sidebar.header("📁 Report Selection")
    selected_report = st.sidebar.selectbox("Select Scan Session", reports)
    
    with open(os.path.join(report_dir, selected_report), "r") as f:
        data = json.load(f)

    # 2. Key Metrics
    info = data['scan_info']
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Assets", info['total_assets'])
    c2.metric("Anomalies", info['anomalies_found'], delta_color="inverse")
    c3.metric("Target", os.path.basename(info['target_path']))
    c4.metric("Device ID", info['device_uuid'][:8])

    # 3. Data Processing Logic
    df = pd.DataFrame(data['findings'])
    
    # Priority Ranking Logic
    def get_rank(row):
        if "SIG MATCH" in str(row['priority']): return "🔴 CRITICAL"
        if row['entropy'] > 7.8: return "🟡 SUSPICIOUS"
        if row['state'] == "MODIFIED": return "🟠 MODIFIED"
        return "⚪ STANDARD"

    # Magic Number Decoder
    magic_map = {
        "4D5A": "Windows Exec (EXE/DLL)",
        "504B": "Archive (ZIP/APK)",
        "2550": "Document (PDF)",
        "7F45": "Linux Exec (ELF)",
        "5468": "Plain Text",
        "E9D5": "Bootloader (Binary)"
    }
    
    def decode_magic(hex_val):
        prefix = str(hex_val)[:4].upper()
        return magic_map.get(prefix, f"Unknown ({prefix})")

    # Apply Logic
    df['Level'] = df.apply(get_rank, axis=1)
    df['Type'] = df['magic'].apply(decode_magic)
    
    # Sidebar Filters
    st.sidebar.markdown("---")
    st.sidebar.header("🔍 Analysis Filters")
    min_entropy = st.sidebar.slider("Minimum Entropy", 0.0, 8.0, 0.0)
    hide_standard = st.sidebar.checkbox("Hide Standard Files", value=True)
    
    # Apply Filters
    filtered_df = df[df['entropy'] >= min_entropy]
    if hide_standard:
        filtered_df = filtered_df[filtered_df['Level'] != "⚪ STANDARD"]

    # 4. Actionable Intelligence Table
    st.subheader(f"🚩 Actionable Intelligence ({len(filtered_df)} items)")
    
    # Styling the table
    st.dataframe(
        filtered_df[['Level', 'Type', 'path', 'entropy', 'state', 'priority']],
        use_container_width=True,
        hide_index=True
    )

    # 5. Visualizations
    col_left, col_right = st.columns(2)
    
    with col_left:
        st.subheader("📊 Threat Distribution")
        st.bar_chart(df['Level'].value_counts())

    with col_right:
        st.subheader("🔒 Entropy Heatmap")
        # Focusing on the top 20 most complex files
        entropy_chart = df.nlargest(20, 'entropy')[['path', 'entropy']].set_index('path')
        st.area_chart(entropy_chart)

    # Footer
    st.markdown("---")
    st.caption(f"Showing report: {selected_report} | Researcher: 404saint")