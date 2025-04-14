# constants.py
import datetime

SCAN_HISTORY = {}
PROJECT_TITLE = "Repo Scanner-X"
HEADING = "# Repo Scanner-X"
HEADING_ALT = "# 🛡️ Git Vulnerability Scanner and AI-based Recommendation System"
GROQ_API_KEY = "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"
GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama3-70b-8192"
SCAN_DATE = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
