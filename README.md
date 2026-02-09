# Cyber Security Monitoring AI Agent

**Autonomous SOC Assistant** - An intermediate-level AI agent that analyzes network logs, detects anomalies, classifies cyber threats, and generates actionable incident reports.

🔗 **[Live Demo](https://cyberaiagent-edac4kkjzv4hsmgrs4k37i.streamlit.app/)** | 📂 **[GitHub Repository](https://github.com/urvashivankar/cyber_ai_agent)**

---

##  Features

- **Log Ingestion**: Upload CSV network logs for analysis
- **Anomaly Detection**: Uses Isolation Forest (scikit-learn) to identify suspicious traffic patterns
- **AI Threat Classification**: Leverages OpenAI/Gemini to classify threats (DDoS, Brute Force, Port Scan, Malware)
- **Incident Reporting**: Generates structured reports with severity levels and mitigation steps
- **Persistent Storage**: SQLite database for historical incident tracking
- **Interactive Dashboard**: Streamlit UI with visualizations and real-time analysis

---

##  Architecture

```
┌─────────────────┐
│  CSV Log File   │
└────────┬────────┘
         │
         ▼
┌─────────────────────────┐
│   Log Analyzer          │
│   (Isolation Forest)    │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│  Threat Classifier      │
│  (LangChain + LLM)      │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│  Incident Manager       │
│  (SQLite Storage)       │
└────────┬────────────────┘
         │
         ▼
┌─────────────────────────┐
│  Streamlit Dashboard    │
└─────────────────────────┘
```

---

##  Project Structure

```
cyber_ai_agent/
│
├── data/
│   └── logs.csv              # Sample network logs
├── agent/
│   ├── __init__.py
│   ├── detector.py           # Anomaly detection (Isolation Forest)
│   ├── classifier.py         # AI threat classification (LangChain)
│   └── report.py             # Incident reporting & SQLite storage
├── app.py                    # Streamlit dashboard
├── requirements.txt          # Python dependencies
└── README.md                 # This file
```

---

##  Setup Instructions

### Prerequisites
- Python 3.8+
- OpenAI API Key OR Google Gemini API Key

### Installation

1. **Clone or navigate to the project directory**
   ```bash
   cd cyber_ai_agent
   ```

2. **Create a virtual environment** (recommended)
   ```bash
   python -m venv venv
   ```

3. **Activate the virtual environment**
   - Windows:
     ```bash
     venv\Scripts\activate
     ```
   - macOS/Linux:
     ```bash
     source venv/bin/activate
     ```

4. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

---

##  Running the Application

1. **Start the Streamlit app**
   ```bash
   streamlit run app.py
   ```

2. **Open your browser** at `http://localhost:8501`

3. **Configure the agent**:
   - Select AI Provider (OpenAI or Gemini)
   - Enter your API key in the sidebar
   - Upload `data/logs.csv` or your own log file

4. **Click "Scan System"** to analyze logs

---

##  Sample Log Format

Your CSV file should have the following columns:

```csv
timestamp,source_ip,destination_port,protocol,bytes_transferred
2024-05-20 08:00:00,192.168.1.10,80,TCP,500
2024-05-20 08:00:05,192.168.1.11,443,TCP,1200
```

A sample file is provided in `data/logs.csv`.

---

##  Component Breakdown

### 1. **detector.py** - Anomaly Detection
- **Class**: `LogAnalyzer`
- **Method**: `detect_anomalies(df)`
- **Algorithm**: Isolation Forest with 5% contamination threshold
- **Features**: Analyzes `bytes_transferred` and `destination_port`

### 2. **classifier.py** - AI Threat Classification
- **Class**: `ThreatClassifier`
- **Method**: `classify_threat(log_entry)`
- **Models**: OpenAI GPT-4 or Google Gemini 1.5 Pro
- **Output**: JSON with attack type, severity, description, mitigation

### 3. **report.py** - Incident Management
- **Class**: `IncidentManager`
- **Database**: SQLite (`incidents.db`)
- **Methods**:
  - `save_incident()`: Store classified threats
  - `get_all_incidents()`: Retrieve history
  - `generate_report()`: Export text report

### 4. **app.py** - Streamlit Dashboard
- **Tabs**:
  - **Dashboard**: Metrics, charts, log table
  - **Incident Reports**: Detailed threat analysis
  - **History**: Database records with export

---

##  Security Notes

- **Never commit API keys** to version control
- Use environment variables or `.env` files for production
- The current implementation stores keys in session state (demo purposes only)

---

##  Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.8+ |
| ML Framework | scikit-learn |
| AI/LLM | LangChain + OpenAI/Gemini |
| Database | SQLite |
| UI | Streamlit |
| Data Processing | Pandas |
| Visualization | Matplotlib |

---

##  Example Workflow

1. **Upload logs** → System loads CSV into Pandas DataFrame
2. **Anomaly detection** → Isolation Forest identifies outliers
3. **AI classification** → LLM analyzes anomalies and categorizes threats
4. **Storage** → Incidents saved to SQLite database
5. **Reporting** → Dashboard displays results with charts and recommendations

---

##  Learning Outcomes

This project demonstrates:
- Machine learning for anomaly detection
- LLM integration for intelligent classification
- Database design for incident tracking
- Full-stack Python development (backend + UI)
- Production-ready code structure

---

##  Future Enhancements

- Real-time log streaming (Apache Kafka)
- Email/Slack alerts for critical threats
- Advanced ML models (LSTM for time-series)
- Multi-file batch processing
- User authentication and role-based access

---


