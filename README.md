
# DevPulse AI
### Autonomous Code Security & Live Vulnerability Researcher

DevPulse AI is an AI-powered code security analysis platform that helps developers identify potential vulnerabilities, detect risky coding patterns, audit dependencies, and research relevant security intelligence.

By combining static code analysis, dependency auditing, live security research with Tavily, and AI-powered explanations using NVIDIA Nemotron through Nebius Token Factory, DevPulse AI helps developers understand potential security risks and explore possible remediation strategies.

## 🚀 Key Features

- **Static Security Analysis** — Scan source files for potentially dangerous coding patterns and security issues.
- **Dependency Auditing** — Analyze project dependencies to identify known security risks where supported by the available audit data.
- **AI-Powered Explanations** — Generate contextual security explanations and remediation guidance using NVIDIA Nemotron.
- **Live Security Research** — Use Tavily to retrieve relevant security intelligence and supporting web sources.
- **Repository Upload** — Upload project files through the web interface for analysis.
- **File-Level Findings** — Review findings, severity levels, and security explanations for analyzed files.
- **Test Coverage** — Automated tests for security detectors and dependency auditing.
- **Resilient Analysis** — AI explanation and live research failures are handled without automatically stopping the core analysis.

## 🧠 How It Works

1. **Upload** — Provide source code through the DevPulse AI interface.
2. **Analyze** — Static security detectors inspect files for suspicious patterns.
3. **Audit** — The dependency auditing service evaluates supported dependency information.
4. **Research** — Tavily searches for relevant security intelligence.
5. **Explain** — NVIDIA Nemotron generates an AI-assisted explanation of detected issues.
6. **Review** — Explore the results and use the supporting information to investigate potential fixes.

## 🛠️ Technology Stack

| Component | Technology |
|---|---|
| Frontend | React, TypeScript, Vite |
| Backend | Node.js, Express, TypeScript |
| Security Analysis | Custom static security detectors |
| Dependency Analysis | Custom dependency auditing service |
| AI Inference | NVIDIA Nemotron via Nebius Token Factory |
| Security Research | Tavily Search API |
| Testing | Automated service and detector tests |
| Version Control | Git and GitHub |

## ⚙️ Getting Started

### Prerequisites

- Node.js and npm
- A Nebius Token Factory API key for AI-powered explanations
- A Tavily API key for live security research

### Installation

Clone the repository:

```bash
git clone https://github.com/ArpitVentures/DevPulse-AI.git
cd DevPulse-AI
npm install
```

### Environment Variables

Create a local `.env` file in the project root and configure the required API credentials:

```env
NEBIUS_API_KEY=your_nebius_api_key
TAVILY_API_KEY=your_tavily_api_key
```

Never commit your `.env` file or expose API keys in public repositories.

### Run Locally

Start the application using the development scripts configured in `package.json`. Check the available scripts before choosing the appropriate frontend and backend commands.

## 🧪 Testing

Run the project's automated tests using the test script configured in `package.json`.

The repository includes tests for:
- Static security detectors
- Dependency auditing

## 🔐 Security & Limitations

DevPulse AI is a security analysis aid, not a replacement for a comprehensive security review.

- Static detection may produce false positives or miss vulnerabilities.
- Dependency audit coverage depends on available package metadata and vulnerability information.
- AI-generated explanations and suggested fixes should be independently verified.
- Live research depends on API availability, network access, and provider limits.
- Do not upload sensitive production code, credentials, or confidential data unless you are authorized to do so.

## 🎯 Project Goal

The goal of DevPulse AI is to make code security analysis more accessible by combining automated detection, live vulnerability research, and AI-assisted explanations in one developer-focused workflow.

## 👨‍💻 Author

**Arpit Srivastava**  
GitHub: [@ArpitVentures](https://github.com/ArpitVentures)

---

*Built for the Nebius × NVIDIA Global AI Hackathon.*
