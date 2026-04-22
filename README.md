# 🛡️ AzureGuard

**Azure Cloud Compliance Monitoring & Alerting Dashboard**

AzureGuard is an open-source tool that continuously monitors your Azure subscription for security misconfigurations, governance gaps, and compliance violations — with a real-time dashboard, automated email alerts, and CI/CD integration via GitHub Actions.

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green?logo=fastapi)
![Azure](https://img.shields.io/badge/Azure-SDK-0078d4?logo=microsoftazure)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

---

## 📸 Features

- **Real-time compliance scoring** (0–100) weighted by severity
- **9 built-in compliance rules** covering Storage, VMs, NSGs, and Governance
- **Interactive dashboard** with score history charts and severity breakdown
- **Automated email alerts** for critical and high-severity findings
- **GitHub Actions CI/CD** with scheduled scans every 6 hours
- **REST API** (FastAPI) for integration with other tools
- **SQLite persistence** — no external database required

---

## 🏗️ Architecture

```
azureguard/
├── collector/            # Azure SDK data collection
│   └── azure_collector.py
├── alerts/               # Compliance engine + email alerts
│   ├── compliance_engine.py
│   └── alert_manager.py
├── api/                  # FastAPI REST backend
│   └── main.py
├── dashboard/            # HTML/JS frontend
│   └── index.html
├── .github/workflows/    # GitHub Actions CI/CD
│   └── ci.yml
├── run_scan.py           # CLI scan runner
└── requirements.txt
```

---

## ⚙️ Setup

### 1. Prerequisites

- Python 3.11+
- Azure subscription (free tier works)
- Azure Service Principal with `Reader` role

### 2. Create Azure Service Principal

```bash
az login
az ad sp create-for-rbac --name "azureguard-sp" --role Reader \
  --scopes /subscriptions/<YOUR_SUBSCRIPTION_ID>
```

Save the output — you'll need `appId`, `password`, and `tenant`.

### 3. Configure environment variables

Create a `.env` file (never commit this to Git):

```env
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-app-id
AZURE_CLIENT_SECRET=your-password
AZURE_SUBSCRIPTION_ID=your-subscription-id

# Optional: email alerts
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your@gmail.com
SMTP_PASS=your-app-password
ALERT_EMAIL=alerts@yourcompany.com
```

### 4. Install dependencies

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 5. Run the dashboard

```bash
uvicorn api.main:app --reload
```

Open http://localhost:8000 and click **Run Scan**.

### 6. Run a CLI scan

```bash
python run_scan.py
```

---

## 🔒 Compliance Rules

| Rule ID  | Name                              | Severity | Resource Type     |
|----------|-----------------------------------|----------|-------------------|
| STG-001  | Storage: HTTPS traffic only       | HIGH     | Storage Account   |
| STG-002  | Storage: Blob public access       | CRITICAL | Storage Account   |
| STG-003  | Storage: Minimum TLS version      | MEDIUM   | Storage Account   |
| VM-001   | VM: Resource tagging              | LOW      | Virtual Machine   |
| VM-002   | VM: OS disk size review           | INFO     | Virtual Machine   |
| NSG-001  | NSG: No wildcard inbound rules    | CRITICAL | Network Sec. Group|
| GOV-001  | Governance: Environment tag       | LOW      | All resources     |

---

## 🚀 CI/CD with GitHub Actions

Add these secrets to your GitHub repository (`Settings → Secrets`):

- `AZURE_TENANT_ID`
- `AZURE_CLIENT_ID`
- `AZURE_CLIENT_SECRET`
- `AZURE_SUBSCRIPTION_ID`
- `SMTP_USER`, `SMTP_PASS`, `ALERT_EMAIL` (optional)

The pipeline runs:
- **On every push**: lint + tests
- **Every 6 hours**: full compliance scan with artifact upload

---

## 📡 API Reference

| Method | Endpoint           | Description                       |
|--------|--------------------|-----------------------------------|
| POST   | `/api/scan`        | Trigger a full Azure scan         |
| GET    | `/api/score`       | Latest compliance score           |
| GET    | `/api/resources`   | Resources from latest snapshot    |
| GET    | `/api/compliance`  | Compliance results (filterable)   |
| GET    | `/api/history`     | Score history for trend chart     |
| GET    | `/api/summary`     | Breakdown by severity             |

Interactive docs available at http://localhost:8000/docs

---

## 🤝 Contributing

Pull requests welcome. To add a new compliance rule, add a `ComplianceRule` entry to `alerts/compliance_engine.py` — no other changes needed.

---

## 📄 License

MIT © [Marlon Henrique Martins](https://github.com/marlondlx)
