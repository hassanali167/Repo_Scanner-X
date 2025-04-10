import gradio as gr
import requests
import subprocess
import os

def verify_github_repo(repo_url, oauth_token=None):
    """Verify if the GitHub repository is accessible."""
    if not repo_url.startswith("https://github.com/"):
        return "❌ Invalid GitHub URL. Please enter a valid GitHub repository URL."
    
    repo_api_url = repo_url.replace("https://github.com/", "https://api.github.com/repos/")
    headers = {"Authorization": f"token {oauth_token}"} if oauth_token else {}

    response = requests.get(repo_api_url, headers=headers)
    
    if response.status_code == 200:
        return "✅ Repository is accessible."
    elif response.status_code == 404:
        return "❌ Repository not found. Check the URL."
    elif response.status_code == 401:
        return "🔑 Unauthorized! Check your OAuth token permissions."
    elif response.status_code == 403:
        return "🔒 Access Denied! You may have exceeded GitHub API rate limits."
    else:
        return f"⚠️ Error: {response.status_code} - {response.json().get('message', 'Unknown error')}"

def run_scanner(scanner, repo_url):
    """Run the selected vulnerability scanner on the given GitHub repository."""
    report = ""
    if scanner == "Trivy":
        # Example Trivy scan command for a Dockerfile or repo
        command = f"trivy repo {repo_url} --format json"
        process = subprocess.run(command, shell=True, capture_output=True, text=True)
        if process.returncode == 0:
            report += f"✅ Trivy Scan completed successfully.\n"
            report += process.stdout.strip()
        else:
            report += f"❌ Trivy Scan failed: {process.stderr.strip()}"
    elif scanner == "SonarQube":
        # Example SonarQube scan command
        command = f"sonar-scanner -Dsonar.projectKey={repo_url} -Dsonar.sources={repo_url}"
        process = subprocess.run(command, shell=True, capture_output=True, text=True)
        if process.returncode == 0:
            report += f"✅ SonarQube Scan completed successfully.\n"
            report += process.stdout.strip()
        else:
            report += f"❌ SonarQube Scan failed: {process.stderr.strip()}"
    elif scanner == "OWASP Dependency-Track":
        # Example OWASP Dependency-Track scan command
        command = f"dependency-track --url {repo_url}"
        process = subprocess.run(command, shell=True, capture_output=True, text=True)
        if process.returncode == 0:
            report += f"✅ OWASP Dependency-Track Scan completed successfully.\n"
            report += process.stdout.strip()
        else:
            report += f"❌ OWASP Dependency-Track Scan failed: {process.stderr.strip()}"
    return report

def process_input(project_name, repo_url, oauth_token, scanners):
    """Process the input and generate a vulnerability report."""
    # Step 1: Verify the GitHub repository
    repo_status = verify_github_repo(repo_url, oauth_token)
    if "❌" in repo_status or "🔒" in repo_status or "🔑" in repo_status:
        return repo_status, ""
    
    # Step 2: Run the selected scanners
    full_report = f"📝 Project: {project_name}\n🔗 Repo: {repo_url}\n{repo_status}\n\n"
    
    if "Trivy" in scanners:
        full_report += "\n--- Trivy Scan ---\n"
        full_report += run_scanner("Trivy", repo_url)
    
    if "SonarQube" in scanners:
        full_report += "\n--- SonarQube Scan ---\n"
        full_report += run_scanner("SonarQube", repo_url)
    
    if "OWASP Dependency-Track" in scanners:
        full_report += "\n--- OWASP Dependency-Track Scan ---\n"
        full_report += run_scanner("OWASP Dependency-Track", repo_url)
    
    # Save the report to a file
    report_path = "vulnerability_report.txt"
    with open(report_path, "w") as report_file:
        report_file.write(full_report)
    
    return full_report, report_path


# UI Components
with gr.Blocks() as ui:
    gr.Markdown("# 🔒 Vulnerability Scanner Tool")
    
    with gr.Row():
        project_name = gr.Textbox(label="Project Name", placeholder="Enter project name")
        repo_url = gr.Textbox(label="GitHub Repository URL", placeholder="https://github.com/user/repo.git")
    
    oauth_token = gr.Textbox(label="OAuth Token (if private)", placeholder="Enter GitHub OAuth Token", type="password")
    
    verify_button = gr.Button("🔍 Verify Repository")
    repo_status_output = gr.Textbox(label="Repository Status", interactive=False)
    
    scanners = gr.CheckboxGroup(
        ["Trivy", "SonarQube", "OWASP Dependency-Track"],
        label="Select Scanners",
        info="Choose one or more security scanners."
    )
    
    scan_button = gr.Button("🔍 Run Scan")
    output = gr.Textbox(label="Scan Output", interactive=False)
    
    download_button = gr.File(label="Download Report", interactive=False)
    
    verify_button.click(verify_github_repo, inputs=[repo_url, oauth_token], outputs=repo_status_output)
    scan_button.click(process_input, 
                      inputs=[project_name, repo_url, oauth_token, scanners], 
                      outputs=[output, download_button])

ui.launch()
