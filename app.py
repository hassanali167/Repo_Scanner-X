import gradio as gr
import requests
import os
import subprocess

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


def execute_commands(commands):
    output_log = []
    current_directory = os.getcwd()
    
    for command in commands.split("\n"):
        command = command.strip()
        if not command:
            continue
        
        if command.startswith("cd "):
            new_directory = command[3:].strip()
            if os.path.exists(new_directory):
                os.chdir(new_directory)
                output_log.append(f"📂 Changed directory to: {new_directory}")
            else:
                os.makedirs(new_directory, exist_ok=True)
                os.chdir(new_directory)
                output_log.append(f"📂 Directory '{new_directory}' did not exist, created and changed to it.")
        else:
            process = subprocess.run(command, shell=True, capture_output=True, text=True)
            if process.returncode == 0:
                output_log.append(f"✅ {command}\n{process.stdout.strip()}")
            else:
                output_log.append(f"❌ {command}\nError: {process.stderr.strip()}")
    
    os.chdir(current_directory)  # Reset to original directory
    return "\n".join(output_log)


def process_input(project_name, repo_url, oauth_token, commands, uploaded_file, scanners):
    repo_status = verify_github_repo(repo_url, oauth_token)
    if "❌" in repo_status or "🔒" in repo_status or "🔑" in repo_status:
        return repo_status, ""
    
    if uploaded_file is not None:
        commands = uploaded_file.decode("utf-8")
    
    execution_result = execute_commands(commands)
    report_content = f"📝 Project: {project_name}\n🔗 Repo: {repo_url}\n{repo_status}\n\n🚀 Executing Commands...\n{execution_result}\n\n🔎 Selected Scanners: {', '.join(scanners)}"
    
    report_path = "command_execution_report.txt"
    with open(report_path, "w") as report_file:
        report_file.write(report_content)
    
    return report_content, report_path


# UI Components
with gr.Blocks() as ui:
    gr.Markdown("# 🔒 Secure Deployment Tool with GitHub Verification")
    
    with gr.Row():
        project_name = gr.Textbox(label="Project Name", placeholder="Enter project name")
        repo_url = gr.Textbox(label="GitHub Repository URL", placeholder="https://github.com/user/repo.git")
    
    oauth_token = gr.Textbox(label="OAuth Token (if private)", placeholder="Enter GitHub OAuth Token", type="password")
    
    verify_button = gr.Button("🔍 Verify Repository")
    repo_status_output = gr.Textbox(label="Repository Status", interactive=False)
    
    with gr.Row():
        commands = gr.Textbox(label="Deployment Commands", placeholder="Enter deployment commands", lines=5)
        file_upload = gr.File(label="Upload Commands (.txt)", type="binary")
    
    scanners = gr.CheckboxGroup([
        "Trivy", "SonarQube", "OWASP Dependency-Track"
    ], label="Select Scanners", info="Choose one or more security scanners.")
    
    deploy_button = gr.Button("🚀 Deploy")
    output = gr.Textbox(label="Output", interactive=False)
    
    download_button = gr.File(label="Download Report", interactive=False)
    
    verify_button.click(verify_github_repo, inputs=[repo_url, oauth_token], outputs=repo_status_output)
    deploy_button.click(process_input, 
                        inputs=[project_name, repo_url, oauth_token, commands, file_upload, scanners], 
                        outputs=[output, download_button])

ui.launch()
