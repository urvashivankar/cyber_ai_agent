import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from agent.detector import LogAnalyzer
from agent.classifier import ThreatClassifier
from agent.report import IncidentManager

# Page configuration
st.set_page_config(
    page_title="Cyber Security Monitoring AI Agent",
    page_icon="🛡️",
    layout="wide"
)

# Title and description
st.title("🛡️ Cyber Security Monitoring AI Agent")
st.markdown("**Autonomous SOC Assistant** - Analyze logs, detect anomalies, classify threats")

# Sidebar for configuration
st.sidebar.header("⚙️ Configuration")
provider = st.sidebar.selectbox("AI Provider", ["openai", "gemini"])
api_key = st.sidebar.text_input("API Key", type="password", help="Enter your OpenAI or Gemini API key")

# File upload
st.sidebar.header("📁 Upload Logs")
uploaded_file = st.sidebar.file_uploader("Upload CSV Log File", type=["csv"])

# Initialize components
if uploaded_file and api_key:
    # Save uploaded file temporarily
    with open("temp_logs.csv", "wb") as f:
        f.write(uploaded_file.getbuffer())
    
    # Scan button
    if st.sidebar.button("🔍 Scan System", type="primary"):
        with st.spinner("Analyzing logs..."):
            # Step 1: Load and detect anomalies
            analyzer = LogAnalyzer()
            df = analyzer.load_logs("temp_logs.csv")
            
            if df.empty:
                st.error("Failed to load logs. Check file format.")
            else:
                df_analyzed = analyzer.detect_anomalies(df)
                
                # Store in session state
                st.session_state['df_analyzed'] = df_analyzed
                st.session_state['scan_complete'] = True
                
                # Step 2: Classify anomalies
                anomalies = df_analyzed[df_analyzed['anomaly'] == -1]
                
                if len(anomalies) > 0:
                    st.session_state['anomalies'] = anomalies
                    
                    # Initialize classifier and incident manager
                    classifier = ThreatClassifier(api_key=api_key, provider=provider)
                    incident_mgr = IncidentManager()
                    
                    classified_incidents = []
                    
                    # Classify each anomaly
                    progress_bar = st.progress(0)
                    for idx, (i, row) in enumerate(anomalies.iterrows()):
                        log_entry = row.to_dict()
                        classification = classifier.classify_threat(log_entry)
                        
                        # Save to database
                        incident_mgr.save_incident(classification, log_entry)
                        classified_incidents.append({**log_entry, **classification})
                        
                        progress_bar.progress((idx + 1) / len(anomalies))
                    
                    st.session_state['classified_incidents'] = classified_incidents
                    st.success(f"✅ Scan complete! Found {len(anomalies)} anomalies.")
                else:
                    st.session_state['anomalies'] = pd.DataFrame()
                    st.success("✅ Scan complete! No anomalies detected.")

# Display results if scan is complete
if st.session_state.get('scan_complete', False):
    df_analyzed = st.session_state['df_analyzed']
    anomalies = st.session_state.get('anomalies', pd.DataFrame())
    
    # Create tabs
    tab1, tab2, tab3 = st.tabs(["📊 Dashboard", "🚨 Incident Reports", "📜 History"])
    
    with tab1:
        st.header("Dashboard Overview")
        
        # Metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Logs", len(df_analyzed))
        with col2:
            st.metric("Anomalies Detected", len(anomalies))
        with col3:
            anomaly_rate = (len(anomalies) / len(df_analyzed) * 100) if len(df_analyzed) > 0 else 0
            st.metric("Anomaly Rate", f"{anomaly_rate:.2f}%")
        with col4:
            critical_count = len([i for i in st.session_state.get('classified_incidents', []) if i.get('severity') == 'Critical'])
            st.metric("Critical Threats", critical_count)
        
        # Visualization
        st.subheader("Log Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Anomaly distribution
            fig, ax = plt.subplots(figsize=(6, 4))
            labels = ['Normal', 'Anomalous']
            sizes = [len(df_analyzed[df_analyzed['anomaly'] == 1]), len(anomalies)]
            colors = ['#2ecc71', '#e74c3c']
            ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
            ax.set_title('Traffic Distribution')
            st.pyplot(fig)
        
        with col2:
            # Attack types
            if st.session_state.get('classified_incidents'):
                attack_types = [i.get('attack_type', 'Unknown') for i in st.session_state['classified_incidents']]
                attack_df = pd.DataFrame({'Attack Type': attack_types})
                attack_counts = attack_df['Attack Type'].value_counts()
                
                fig, ax = plt.subplots(figsize=(6, 4))
                attack_counts.plot(kind='bar', ax=ax, color='#e74c3c')
                ax.set_title('Attack Type Distribution')
                ax.set_xlabel('Attack Type')
                ax.set_ylabel('Count')
                plt.xticks(rotation=45)
                st.pyplot(fig)
        
        # Data table
        st.subheader("Analyzed Logs")
        st.dataframe(df_analyzed, use_container_width=True)
    
    with tab2:
        st.header("Incident Reports")
        
        if st.session_state.get('classified_incidents'):
            for idx, incident in enumerate(st.session_state['classified_incidents']):
                severity_colors = {
                    'Critical': '🔴',
                    'High': '🟠',
                    'Medium': '🟡',
                    'Low': '🟢'
                }
                severity_icon = severity_colors.get(incident.get('severity', 'Unknown'), '⚪')
                
                with st.expander(f"{severity_icon} Incident #{idx+1} - {incident.get('attack_type', 'Unknown')} ({incident.get('severity', 'Unknown')})"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown(f"**Source IP:** `{incident.get('source_ip', 'N/A')}`")
                        st.markdown(f"**Destination Port:** `{incident.get('destination_port', 'N/A')}`")
                        st.markdown(f"**Protocol:** `{incident.get('protocol', 'N/A')}`")
                        st.markdown(f"**Bytes Transferred:** `{incident.get('bytes_transferred', 'N/A')}`")
                    
                    with col2:
                        st.markdown(f"**Attack Type:** `{incident.get('attack_type', 'N/A')}`")
                        st.markdown(f"**Severity:** `{incident.get('severity', 'N/A')}`")
                        st.markdown(f"**Timestamp:** `{incident.get('timestamp', 'N/A')}`")
                    
                    st.markdown("**Description:**")
                    st.info(incident.get('description', 'No description available'))
                    
                    st.markdown("**Mitigation Steps:**")
                    st.success(incident.get('mitigation', 'No mitigation steps available'))
        else:
            st.info("No incidents to display. Run a scan to detect threats.")
    
    with tab3:
        st.header("Incident History")
        
        incident_mgr = IncidentManager()
        history_df = incident_mgr.get_all_incidents()
        
        if not history_df.empty:
            st.dataframe(history_df, use_container_width=True)
            
            # Download report
            if st.button("📥 Download Full Report"):
                report = incident_mgr.generate_report()
                st.download_button(
                    label="Download Report as TXT",
                    data=report,
                    file_name="incident_report.txt",
                    mime="text/plain"
                )
        else:
            st.info("No historical incidents found.")

else:
    # Welcome screen
    st.info("👈 Upload a log file and enter your API key to begin scanning.")
    
    st.markdown("""
    ### How to Use:
    1. **Select AI Provider** (OpenAI or Gemini)
    2. **Enter API Key** in the sidebar
    3. **Upload CSV Log File** with columns: `timestamp`, `source_ip`, `destination_port`, `protocol`, `bytes_transferred`
    4. **Click 'Scan System'** to analyze logs
    
    ### Features:
    - 🔍 **Anomaly Detection** using Isolation Forest
    - 🤖 **AI-Powered Threat Classification** (DDoS, Brute Force, Port Scan, Malware)
    - 📊 **Real-time Dashboard** with visualizations
    - 💾 **Persistent Storage** in SQLite database
    - 📄 **Incident Reports** with mitigation recommendations
    """)
