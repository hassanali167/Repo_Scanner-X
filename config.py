# Configuration settings and input validation for Repo Scanner-X.
# Defines constants like API keys, endpoints, and scan history.
# Provides functions to validate GitHub URLs and tokens.


import os
import re
from dotenv import load_dotenv

load_dotenv()

# Configuration variables
SCAN_HISTORY = {}
PROJECT_TITLE = "Repo Scanner-X"
HEADING = "# Repo Scanner-X"
HEADING_ALT = "# 🛡️ Github Repo Vulnerability Scanner and AI-based Recommendation System"
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama3-70b-8192"

# Input validation functions
def is_valid_github_url(url: str) -> bool:
    if re.search(r'[\s;|&`$><]', url):
        return False
    pattern = r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\.git)?$"
    return re.match(pattern, url) is not None

def is_valid_token(token: str) -> bool:
    if not token:
        return True
    if re.search(r'[\s;|&`$><]', token):
        return False
    return bool(re.match(r"^[A-Za-z0-9_\-]{20,100}$", token))