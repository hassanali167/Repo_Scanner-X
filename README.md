# 🛡️ Repo Scanner-X

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Gradio](https://img.shields.io/badge/Gradio-4.27.0-blue)](https://gradio.app/)

## ⚡ Summary

**Repo Scanner-X** is a powerful GitHub repository vulnerability scanner and AI-based recommendation system. It integrates Trivy for deep scanning of repositories and utilizes LLM (LLaMA 3) via the Groq API to generate insightful and professional recommendations on detected vulnerabilities.

---

## 🔒 Privacy Note
- Your GitHub tokens and API keys are never logged or stored.
- All scans are performed in temporary directories that are securely deleted after use.
- No repository data is retained after the scan session ends.

---

## 🚀 Features

- ✅ GitHub Repository Verification (public or private)
- 🔍 Clone and scan repositories using **Trivy**
- 📂 Detect:
  - Vulnerabilities
  - Secrets
  - Misconfigurations
  - License issues
- 🤖 AI-Powered Report Generator using **LLaMA 3 (Groq)**
- 📄 Downloadable reports (Trivy raw + AI analysis)
- 🧠 AI Suggests:
  - Top 3 Critical Vulnerabilities (with CVE links if possible)
  - Remediation Steps
  - Known Exploits & Attack Techniques
- 📈 Tracks scan statistics per project
- 🌐 Clean Gradio UI with theme customization
- 🕶️ Accessible and keyboard-friendly UI

---

## 🛠️ Setup Instructions

### 1. Clone the Repo

```bash
git clone https://github.com/your-username/repo-scanner-x.git
cd repo-scanner-x
```

### 2. Install Requirements

```bash
pip install -r requirements.txt
```

### 3. Install Trivy (if not installed)

Follow the instructions at:  
🔗 https://aquasecurity.github.io/trivy/v0.37.0/installation/

### 4. Create a .env File for API Keys

Create a `.env` file in your project root with the following content:

```
GROQ_API_KEY=your_real_groq_api_key_here
```

This keeps your API keys secure and out of the codebase.

### 5. Run the App

```bash
python3 app.py
```

This will launch a Gradio web interface for interaction.

### 🔐 GitHub Token (Optional)

To scan private repositories or avoid GitHub API rate limits, generate a Personal Access Token and paste it in the UI.

---

## ✨ Usage Example

1. Enter a project name and the GitHub repository URL.
2. (Optional) Enter your GitHub token for private repos.
3. Click **Verify Repo** to check access.
4. Click **Run Scan + AI Recommendation** to start scanning.
5. Download the reports for your records.

---

## 🧩 Troubleshooting

- **Trivy not found:** Ensure Trivy is installed and available in your PATH.
- **API key errors:** Double-check your `.env` file and restart the app after changes.
- **Timeouts:** Network issues or large repositories may cause timeouts. Try again or check your connection.
- **Permission denied:** For private repos, ensure your token has the correct scopes.

---

## 🧪 Testing

- Placeholder for unit and integration tests. (See `tests/` directory in future versions.)

---

## 🛠️ Future Features (Planned)
- Batch/multi-repo scanning
- Plugin system for custom scanners/analysis
- REST API for automation and CI/CD
- User authentication and scan history
- Scheduled scans and notifications
- Internationalization (i18n) for multiple languages
- Improved logging and monitoring

---

## 📜 License

MIT License © 2025

---

## 👨‍💻 Contributing

1. Fork this repo  
2. Create your feature branch:  
   ```bash
   git checkout -b feature/my-feature
   ```
3. Commit your changes:  
   ```bash
   git commit -m 'Add new feature'
   ```
4. Push to the branch:  
   ```bash
   git push origin feature/my-feature
   ```
5. Open a Pull Request

---

## 💬 Contact

If you encounter any issues or have suggestions, feel free to open an issue or reach out to:

📧 alihassanali119683@gmail.com
📧 su439178@gmail.com  
🔗 [linkedin.com/in/hassanali202](https://www.linkedin.com/in/hassanali202/)
🔗 [linkedin.com/in/safi-ullah-54464525b](https://www.linkedin.com/in/safi-ullah-54464525b/)
