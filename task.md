# Paradox Project Tracker

## Phase 1: Foundation (Complete)
- [x] Create directory structure
- [x] Backend: requirements.txt + virtual env
- [x] Backend: FastAPI skeleton with CORS + WebSocket
- [x] Backend: Pydantic models (ScanRequest, Finding, etc.)
- [x] Frontend: Scaffold Vite + React
- [x] Frontend: Design system (index.css cyberpunk style)
- [x] Infra: finch-compose.yml, SAM template, K8s manifests, Containerfiles

## Phase 2: Open Source Core (Complete)
- [x] OpenSearch client (with in-memory fallback)
- [x] Cedar engine with policy loading
- [x] Cedar policies (OWASP, privacy, agent behavior)
- [x] PartyRock integration module
- [x] Firecracker/isolation manager

## Phase 3: Agent Toolset (Complete)
- [x] Attack library (hardcoded payloads)
- [x] HTTP tools (Strands @tool)
- [x] HTML tools (Strands @tool)
- [x] Security tools (Strands @tool)

## Phase 4: Security & Privacy Scans (Complete)
- [x] Security Strands agent
- [x] Tracker database + privacy tools
- [x] Privacy Strands agent

## Phase 5: Red-Team Agent Battle (Complete)
- [x] Attack categories + redteam tools
- [x] Defender agent (demo target)
- [x] Red-team Strands agent

## Phase 6: API & Orchestration (Complete)
- [x] Scan orchestrator (concurrent execution)
- [x] WebSocket event streaming
- [x] Score calculation
- [x] Lambda handlers (SAM)

## Phase 7: UI Implementation (Complete)
- [x] App.jsx with routing
- [x] Landing page + ScanInput
- [x] ScanDashboard page
- [x] AttackFeed component
- [x] NetworkGraph component (SVG)
- [x] BattleArena component
- [x] ScoreGauge component
- [x] FindingsList + FindingDetail
- [x] Results page
- [x] History page
- [x] Header + ToolsBadge
- [x] API client + WebSocket utils

## Phase 8: Final Polish & Deployment (Complete)
- [x] EKS Distro K8s manifests
- [x] EKS Anywhere cluster config
- [x] Firecracker VM config
- [x] Corretto OpenSearch Containerfile
- [x] Backend + Frontend Containerfiles
- [x] Setup scripts (sh + ps1)
- [x] README.md
