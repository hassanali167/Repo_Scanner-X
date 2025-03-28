import gradio as gr

def process_input(project_name, repo_url, oauth_token, commands, uploaded_file, scanners):
    """Handles user input and prepares for scanning and deployment."""
    if uploaded_file is not None:
        commands = uploaded_file.decode("utf-8")
    
    result = f"Project: {project_name}\nRepo: {repo_url}\n"
    if oauth_token:
        result += "Using OAuth Authentication\n"
    result += f"Commands:\n{commands}\nSelected Scanners: {', '.join(scanners)}"
    
    return result

# UI Components
with gr.Blocks() as ui:
    gr.Markdown("# 🔒 Secure Deployment Tool")
    
    # Project & Repo Input
    with gr.Row():
        project_name = gr.Textbox(label="Project Name", placeholder="Enter project name")
        repo_url = gr.Textbox(label="GitHub Repository URL", placeholder="https://github.com/user/repo.git")
    
    oauth_token = gr.Textbox(label="OAuth Token (if private)", placeholder="Enter GitHub OAuth Token", type="password")
    
    # Command Input (Text & File Upload)
    with gr.Row():
        commands = gr.Textbox(label="Deployment Commands", placeholder="Enter deployment commands", lines=5)
        file_upload = gr.File(label="Upload Commands (.txt)", type="binary")
    
    # Scanner Selection
    scanners = gr.CheckboxGroup(
        ["Trivy", "SonarQube", "OWASP Dependency-Track"],
        label="Select Scanners",
        info="Choose one or more security scanners."
    )
    
    # Deploy Button
    deploy_button = gr.Button("🚀 Deploy")

    # Output Section
    output = gr.Textbox(label="Output", interactive=False)

    # Event Handling
    deploy_button.click(
        process_input,
        inputs=[project_name, repo_url, oauth_token, commands, file_upload, scanners],
        outputs=output
    )

# Run Web App
ui.launch()
