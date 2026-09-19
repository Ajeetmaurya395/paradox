# Paradox — AI-Powered Security, Privacy & Agent Red-Team Platform

> *"See what hackers see, before they do."*

Paradox is a next-generation AI security platform that stress-tests websites and AI agents using advanced adversarial techniques. It runs three parallel scans to uncover vulnerabilities, privacy data leaks, and AI weaknesses.

Built exclusively with AWS Open-Source technologies.

---

## ⚡ Three Modes, One Platform

### 🔒 Mode 1: Website Security Scan
Discovers traditional web vulnerabilities (OWASP Top 10) including XSS, SQL injections, broken auth, and path traversals using Strands Agents SDK to orchestrate complex attacks.

### 👁️ Mode 2: Privacy Leak Detector
Maps hidden third-party trackers, cookies, and unauthorized data flows. Generates a live interactive Network Graph showing exactly where your user data is being sent.

### 🤖 Mode 3: AI Agent Red-Team (Battle Arena)
Launches a split-screen battle where our Red-Team AI attacks your chatbot endpoints with prompt injections, jailbreaks, and role-confusion attacks to test its resilience.

---

## 🏗️ Architecture & AWS Open-Source Stack

This project heavily utilizes the AWS open-source ecosystem:

- **Strands Agents SDK**: Orchestrates the Security, Privacy, Red-Team, and Defender AI agents.
- **PartyRock**: Provides external chatbot targets for red-teaming and generates executive summaries.
- **Finch & Firecracker**: Powers the Scan Isolation Manager, running scans in isolated containers/micro-VMs.
- **EKS Anywhere & EKS Distro**: Infrastructure scaffolding provided for enterprise-grade Kubernetes deployment.
- **SAM CLI & LocalStack**: Serverless backend configurations provided.
- **OpenSearch (on Corretto)**: Data persistence for scan results and vulnerability history.
- **Cedar**: Policy engine evaluating findings against OWASP and GDPR compliance standards.

---

## 🚀 Quick Start (Local Development)

### Prerequisites
- Python 3.10+
- Node.js 18+
- [Ollama](https://ollama.com/) (Required for local LLM inference)

### 1. Setup Environment
Run the setup script for your platform:

**Windows (PowerShell):**
```powershell
.\setup.ps1
```

**Linux/macOS:**
```bash
chmod +x setup.sh
./setup.sh
```

### 2. Start Ollama
Ensure Ollama is running with the specified model:
```bash
ollama run qwen3.8:27b
```

### 3. Run Backend (FastAPI)
```bash
cd backend
# Windows: .\venv\Scripts\Activate.ps1
# Linux/mac: source venv/bin/activate
uvicorn app.main:app --reload
```

### 4. Run Frontend (Vite + React)
```bash
cd frontend
npm run dev
```

Open `http://localhost:5173` in your browser.

---

## 🛡️ Target Endpoints for Testing
- **Vulnerable Web App**: `http://testphp.vulnweb.com`
- **Local Defender Agent**: `http://localhost:8000/api/agent/chat`
- **PartyRock Agent**: `https://partyrock.aws/u/paradox/techstore-bot`

---

## 📸 Cyberpunk UI

The frontend is built with React and Vanilla CSS, featuring a bespoke "Dark Cyberpunk" design system with glassmorphism, animated network graphs, and live battle arena split-screens.
