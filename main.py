
# Main entry point for the Repo Scanner-X application.
# Sets up the Gradio UI for repository scanning and displays results.
# Handles user inputs, verification, scanning, and file downloads.

import gradio as gr
from config import PROJECT_TITLE, HEADING, HEADING_ALT
from utils import verify_github_repo
from scanner import run_scan

with gr.Blocks(theme=gr.themes.Monochrome(), css="""
    .gr-button { 
        border-radius: 12px; 
        font-weight: bold; 
        padding: 12px;
        font-size: 18px;
        outline: none;
    }
    .gr-button-primary {
        background-color: #444444;
        color: white;
    }
    .gr-button-secondary {
        background-color: #D3D3D3;
        color: black;
    }
    .gr-button:focus,
    .gr-button:active {
        outline: 2px solid #00bfff !important;
        box-shadow: 0 0 0 2px #00bfff33 !important;
    }
    .gr-markdown { 
        color: #4A4A4A; 
        font-family: 'Arial', sans-serif; 
        font-size: 24px;
        font-weight: bold;
        text-align: center;
    }
    .gr-textbox { 
        background-color: #F9F9F9;
        color: #333;
        font-family: 'Arial', sans-serif;
        font-size: 16px;
        padding: 10px;
    }
    .gr-file { 
        background-color: #032d3e; 
        color: white; 
        padding: 12px;
        font-size: 16px;
    }
    .gr-row { 
        justify-content: center; 
    }
    .gr-textbox, .gr-button { 
        margin-bottom: 15px;
    }
    .visually-hidden {
        position: absolute;
        width: 1px;
        height: 1px;
        padding: 0;
        margin: -1px;
        overflow: hidden;
        clip: rect(0,0,0,0);
        border: 0;
    }
    .gr-markdown h1 {
        color: #444444;
        font-size: 28px;
        font-weight: bold;
        text-align: center;
    }
    .gr-markdown h3 {
        color: #777777;
        font-size: 22px;
        font-weight: normal;
        text-align: center;
    }
    """) as ui:
    gr.HTML('<h1 class="visually-hidden">Repo Scanner-X: GitHub Vulnerability Scanner and AI-based Recommendation System</h1>')
    gr.Markdown(f"{HEADING}\n{HEADING_ALT}")

    with gr.Row():
        project_name = gr.Textbox(label="Project Name", placeholder="e.g., MyApp-V1")
        repo_url = gr.Textbox(label="GitHub Repo URL", placeholder="https://github.com/user/repo.git")
    token = gr.Textbox(label="OAuth Token (Optional)", type="password")

    verify_btn = gr.Button("🔍 Verify Repo", variant="secondary")
    repo_status = gr.Textbox(label="Repository Status", interactive=False)

    scan_btn = gr.Button("🛠️ Run Scan + AI Recommendation", variant="primary")
    output_msg = gr.Textbox(label="Status")

    gr.Markdown("### 📊 Trivy Scan Output")
    trivy_text = gr.Textbox(label="Trivy Report (Raw)", lines=10, interactive=False)

    gr.Markdown("### 🧠 AI Recommendation")
    ai_text = gr.Textbox(label="AI Analysis", lines=10, interactive=False)

    gr.Markdown("### 📁 Download Reports")
    with gr.Row():
        trivy_file_output = gr.File(label="Trivy Report", interactive=False)
        ai_file_output = gr.File(label="AI Report", interactive=False)

    scan_stats = gr.Textbox(label="Project Scan Stats", interactive=False)

    def verify_with_progress(repo_url, token):
        yield "⏳ Verifying repository..."
        result = verify_github_repo(repo_url, token)
        yield result

    def scan_with_progress(project_name, repo_url, token):
        yield "⏳ Running scan and AI analysis...", None, None, "", "", ""
        result = run_scan(project_name, repo_url, token)
        yield result

    verify_btn.click(verify_with_progress, inputs=[repo_url, token], outputs=repo_status, show_progress=True)

    scan_btn.click(scan_with_progress,
                   inputs=[project_name, repo_url, token],
                   outputs=[output_msg, trivy_file_output, ai_file_output, trivy_text, ai_text, scan_stats],
                   show_progress=True)

ui.launch()