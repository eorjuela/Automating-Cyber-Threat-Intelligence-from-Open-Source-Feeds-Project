
# 🛡️ CTI Collection System
Automating Cyber Threat Intelligence Collection from Open-Source Feeds

## Overview

This project implements an automated Cyber Threat Intelligence (CTI) collection system designed to collect, normalize, store, and visualize Indicators of Compromise (IoCs) from multiple open-source threat intelligence feeds.

The system addresses the fragmentation, volume, and heterogeneity of open-source CTI by providing a fully automated, modular pipeline that improves efficiency, reduces manual workload, and enables actionable security insights through analytics and visualization.

This project was developed as part of a Bachelor’s Thesis in Systems and Computing Engineering at Universidad de los Andes.

---

## Key Features

- Automated ingestion from multiple OSINT feeds  
- IoC normalization and automatic type detection  
- Deduplication and historical tracking  
- Centralized SQLite database  
- Scheduled and on-demand collection  
- Comprehensive logging and statistics  
- Interactive Streamlit dashboard  
- Data export (CSV / JSON)

---

## Architecture

The system follows a modular, layered architecture:

1. Data Sources (OTX, AbuseIPDB, MalwareBazaar)  
2. Ingestion Layer (API-based collectors)  
3. Processing Layer (Normalization and validation)  
4. Storage Layer (SQLite + deduplication)  
5. Presentation Layer (Streamlit dashboard)  
6. Management Layer (Scheduler, logging, configuration)

---

## Project Structure

```
.
├── main.py                # System entry point
├── api_ingestion.py       # Threat feed ingestion (OTX, AbuseIPDB, MalwareBazaar)
├── normalization.py       # IoC detection, validation, normalization
├── database.py            # SQLite schema and data access layer
├── scheduler.py           # Collection orchestration and scheduling
├── dashboard.py           # Streamlit visualization dashboard
├── config.py              # Centralized configuration
├── cti_thesis.db          # SQLite database (generated at runtime)
├── logs/
│   └── cti_collector.log  # System logs
└── README.md
```

---

## Supported IoC Types

- IP addresses (IPv4 / IPv6)  
- URLs  
- Domains  
- File hashes (MD5, SHA1, SHA256)

---

## Data Sources

| Source         | IoC Type | Authentication |
|----------------|----------|----------------|
| AlienVault OTX | URLs     | API Key        |
| AbuseIPDB      | IPs      | API Key        |
| MalwareBazaar  | Hashes   | None           |

---

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/your-repo/cti-collection-system.git
cd cti-collection-system
```

### 2. Install dependencies
```bash
pip install requests schedule streamlit pandas plotly
```

### 3. (Optional) Set API keys as environment variables
```bash
export OTX_API_KEY="your_otx_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
```

If not set, the system will use the keys defined in `config.py` (for academic/demo purposes).

---

## Usage

### Run full system with scheduling
```bash
python main.py
```

This will:
- Execute an initial collection  
- Schedule daily collection at 09:00  
- Run continuously until interrupted  

### Run a single collection cycle (recommended for testing)
```bash
python main.py single
```

### Show system statistics
```bash
python main.py stats
```

### Launch the dashboard
```bash
streamlit run dashboard.py
```

The dashboard provides:
- IoC trends over time  
- Distribution by type, source, threat level, and confidence  
- Top IoCs by frequency  
- Collection success metrics  
- CSV and JSON export  

---

## Database Schema

### IoCs Table

Stores normalized and deduplicated IoCs with historical tracking.

Key fields:
- indicator  
- type  
- source  
- first_seen  
- last_seen  
- seen_count  
- confidence  
- threat_level  
- metadata  

### Collection Logs table

Tracks each automated collection run:
- source  
- time  
- processed / new / updated IoCs  
- status and errors  

---

## Evaluation & Results

- Processes 8,000–12,000 IoCs per run  
- Accumulated 37,000+ unique IoCs  
- Demonstrated effective deduplication (average seen count ≈ 4)  
- Automated collection significantly outperformed manual methods  
- Dashboard enabled rapid identification of trends and dominant threat sources  

---

## Limitations

- Free-tier API rate limits  
- Some feeds provide limited contextual information  
- SQLite is suitable for prototyping but not large-scale deployment  

---

## Future Work

- Machine-learning-based threat classification  
- Integration of additional OSCTI feeds  
- Alerting and automated defensive actions  
- Migration to PostgreSQL or Elasticsearch  
- SOC / SIEM integration  

---

## Author

**Esteban Orjuela Perdomo**  
Systems and Computing Engineering  
Universidad de los Andes  

**Advisor:**  
Carlos Andrés Lozano Garzón
