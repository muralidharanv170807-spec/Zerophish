# 🛡️ ZeroPhish
### AI-Powered Multi-Modal Phishing Detection System

**ZeroPhish** is a cybersecurity application designed to identify potential phishing threats through multiple input formats. It provides URL, message, QR-code, and screenshot scanning through a unified analysis platform.

The system analyzes submitted content and presents security assessments to help users recognize suspicious digital content.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔗 URL Scanner | Analyzes submitted URLs for suspicious characteristics |
| 💬 Message Scanner | Examines message content for phishing indicators |
| 📱 QR Code Scanner | Analyzes QR-code content for potential phishing links |
| 🖼️ Screenshot Scanner | Examines submitted screenshots for suspicious content |
| 📊 Risk Assessment | Presents security analysis results |
| 📜 Scan History | Maintains scan records using SQLite |

---

## 🏗️ System Architecture

```text
              USER INPUT
                  |
       +----------+----------+
       |          |          |
      URL      MESSAGE    QR CODE
       |          |          |
       +----------+----------+
                  |
           SCREENSHOT INPUT
                  |
                  v
          REACT FRONTEND
                  |
                  v
            FASTAPI BACKEND
                  |
          DETECTION MODULES
                  |
                  v
          SECURITY ANALYSIS
                  |
                  v
          RESULT GENERATION
                  |
                  v
           SQLITE DATABASE
             SCAN HISTORY
```

---

## 🛠️ Technology Stack

### Frontend
- React
- TypeScript
- Vite
- Tailwind CSS

### Backend
- Python
- FastAPI
- Uvicorn

### Machine Learning and Data Processing
- Scikit-learn
- NumPy
- Pandas
- Joblib

### Database
- SQLite

---

## 📂 Project Structure

```text
ZeroPhish/
│
├── backend/
│   ├── app/
│   │   ├── detectors/
│   │   ├── ml/
│   │   ├── database/
│   │   └── main.py
│   │
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   ├── public/
│   ├── package.json
│   └── vite.config.ts
│
├── data/
├── README.md
└── .gitignore
```

*The directory overview is simplified; consult the repository for the complete implementation.*

---

## ⚙️ Installation and Setup

### Prerequisites

- Python version compatible with the pinned backend dependencies
- Node.js and npm
- Git

### 1. Clone the Repository

```bash
git clone https://github.com/muralidharanv170807-spec/Zerophish.git
cd Zerophish/ZeroPhish-main
```

### 2. Create a Python Virtual Environment

```powershell
python -m venv .venv
```

### 3. Install Backend Dependencies

```powershell
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
```

### 4. Start the Backend

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Backend API:

`http://127.0.0.1:8000`

Interactive API documentation:

`http://127.0.0.1:8000/docs`

### 5. Install Frontend Dependencies

Open a second terminal:

```powershell
cd frontend
npm ci
```

### 6. Start the Frontend

```powershell
npm run dev -- --host 127.0.0.1
```

Frontend:

`http://127.0.0.1:5173`

The Vite development server proxies `/api` requests to the FastAPI backend.

---

## 🧠 Machine Learning and Model Compatibility

The application includes machine-learning artifacts used by its detection pipeline.

**Important compatibility consideration:**

The repository documentation reports that the model artifacts were created using scikit-learn 1.6.1, while the inspected working environment reports version 1.9.1.

Use the pinned scikit-learn 1.6.1 runtime for deployment unless model compatibility has been verified with another version.

---

## 🗄️ Database

ZeroPhish uses SQLite for local application data and scan history.

The database and model artifacts should be maintained in persistent, access-controlled storage.

---

## 🔐 Security Considerations

- Do not enter real passwords or sensitive credentials during testing.
- Treat suspicious links as untrusted.
- Do not open suspicious links on your normal browser as part of testing.
- Keep database files and model artifacts protected.
- Configure production CORS, HTTPS, request-size limits, and access controls before public deployment.

---

## 🚀 Future Enhancements

- Modern transformer-based phishing message classification
- Improved URL feature extraction and model generalization
- Isolated dynamic URL and webpage analysis
- Enhanced QR-code threat detection
- Advanced screenshot and webpage analysis
- Improved explainable AI and risk assessment
- Persistent cloud database integration
- Docker-based deployment
- Browser extension integration

---

## 👥 Project Team

**Project:** ZeroPhish  
**Domain:** Cybersecurity & Artificial Intelligence  
**Project Category:** AI-Based Phishing Detection

---

## 🎯 Objective

To develop a unified phishing detection platform that analyzes multiple forms of digital content and helps users identify potential cybersecurity threats.

**ZeroPhish — Detect Before You Click.**
