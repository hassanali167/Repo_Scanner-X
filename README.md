# 🛡️ Repo Scanner-X

## Overview

**Repo Scanner-X** is a powerful GitHub repository vulnerability scanner and AI-based recommendation system. It integrates Trivy for deep scanning of repositories and utilizes LLM (LLaMA 3) via the Groq API to generate insightful and professional recommendations on detected vulnerabilities.

> ⚡ Scan, Detect, and Remediate vulnerabilities — in one go!

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
  - Top 3 Critical Vulnerabilities
  - Remediation Steps
  - Known Exploits & Attack Techniques
- 📈 Tracks scan statistics per project
- 🌐 Clean Gradio UI with theme customization

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

## 📦 Requirements

- Python 3.8+
- Trivy
- Python Packages:
  - requests
  - gradio
  - uuid
  - re
  - subprocess

Install them using:

```bash
pip install -r requirements.txt
```

---

## ✨ Example Output

- ✅ Repository accessible
- 📊 Raw scan results from Trivy
- 🧠 AI Analysis on scan results with actionable security insights
- 📄 Downloadable reports

---

## 📜 License

MIT License © 2025 [Your Name or Organization]

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
🔗 [linkedin.com/in/safi-ullah-54464525b]([linkedin.com/in/safi-ullah-54464525b](https://www.linkedin.com/in/safi-ullah-54464525b/))
