import gradio as gr
import requests

def verify_github_repo(repo_url, oauth_token=None):
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

def process_input(project_name, repo_url, oauth_token, scanners):
    repo_status = verify_github_repo(repo_url, oauth_token)
    if "❌" in repo_status or "🔒" in repo_status or "🔑" in repo_status:
        return repo_status, ""
    
    report_content = f"📝 Project: {project_name}\n🔗 Repo: {repo_url}\n{repo_status}\n\n🔎 Selected Scanners: {', '.join(scanners)}"
    
    report_path = "scanner_report.txt"
    with open(report_path, "w") as report_file:
        report_file.write(report_content)
    
    return report_content, report_path


# UI Components
with gr.Blocks() as ui:
    gr.Markdown("# 🛡️ Git Vulnerability Scanner & AI Based Recommendation System")
    
    with gr.Row():
        project_name = gr.Textbox(label="Project Name", placeholder="Enter project name")
        repo_url = gr.Textbox(label="GitHub Repository URL", placeholder="https://github.com/user/repo.git")
    
    oauth_token = gr.Textbox(label="OAuth Token (if private)", placeholder="Enter GitHub OAuth Token", type="password")
    
    verify_button = gr.Button("🔍 Verify Repository")
    repo_status_output = gr.Textbox(label="Repository Status", interactive=False)
    
    scanners = gr.CheckboxGroup([
        "Trivy", "SonarQube", "OWASP Dependency-Track"
    ], label="Select Scanners", info="Choose one or more security scanners.")
    
    deploy_button = gr.Button("🚀 Deploy")
    output = gr.Textbox(label="Output", interactive=False)
    
    download_button = gr.File(label="Download Report", interactive=False)
    
    verify_button.click(verify_github_repo, inputs=[repo_url, oauth_token], outputs=repo_status_output)
    deploy_button.click(process_input, 
                        inputs=[project_name, repo_url, oauth_token, scanners], 
                        outputs=[output, download_button])

ui.launch()
