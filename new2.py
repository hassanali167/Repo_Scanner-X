import subprocess
import os
import sys
import git
from pathlib import Path
import json

# Define paths to scan tools
TRIVY_PATH = "/usr/local/bin/trivy"
SONAR_SCANNER_PATH = "/usr/local/bin/sonar-scanner"
DEPENDENCY_CHECK_PATH = "/opt/dependency-check/bin/dependency-check.sh"

# Define function to clone the repository if not already cloned
def clone_repo(repo_url, repo_name):
    if not Path(repo_name).exists():
        print(f"Cloning repository {repo_url}...")
        git.Repo.clone_from(repo_url, repo_name)
    else:
        print(f"Repository {repo_name} already exists. Pulling latest changes...")
        repo = git.Repo(repo_name)
        repo.remotes.origin.pull()

# Run Trivy scan
def run_trivy_scan(repo_name):
    print("\n--- Running Trivy Scan ---")
    try:
        result = subprocess.run([TRIVY_PATH, "repo", repo_name], capture_output=True, text=True, check=True)
        print("Trivy Scan completed successfully.")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print("Trivy Scan failed:", e.stderr)
        return None

# Run SonarQube scan
def run_sonarqube_scan(repo_name):
    print("\n--- Running SonarQube Scan ---")
    try:
        result = subprocess.run([SONAR_SCANNER_PATH, "-Dsonar.projectKey=" + repo_name, "-Dsonar.sources=" + repo_name], capture_output=True, text=True, check=True)
        print("SonarQube Scan completed successfully.")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print("SonarQube Scan failed:", e.stderr)
        return None

# Run OWASP Dependency-Check scan
def run_dependency_check_scan(repo_name):
    print("\n--- Running OWASP Dependency-Check Scan ---")
    try:
        result = subprocess.run([DEPENDENCY_CHECK_PATH, "--project", repo_name, "--scan", repo_name], capture_output=True, text=True, check=True)
        print("OWASP Dependency-Check Scan completed successfully.")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print("OWASP Dependency-Check Scan failed:", e.stderr)
        return None

# Save the results to a report
def save_report(repo_name, trivy_report, sonar_report, dependency_check_report):
    report_filename = f"{repo_name}_scan_report.json"
    with open(report_filename, "w") as f:
        json.dump({
            "repository": repo_name,
            "trivy_scan": trivy_report,
            "sonar_scan": sonar_report,
            "dependency_check_scan": dependency_check_report
        }, f, indent=4)
    print(f"Report saved as {report_filename}")

# Main function to drive the script
def main():
    # Get the repository URL from the user
    repo_url = input("Enter the GitHub repository URL: ")
    repo_name = repo_url.split("/")[-1].replace(".git", "")

    # Clone the repo
    clone_repo(repo_url, repo_name)

    # Perform the selected scans
    trivy_report = run_trivy_scan(repo_name)
    sonar_report = run_sonarqube_scan(repo_name)
    dependency_check_report = run_dependency_check_scan(repo_name)

    # Save the reports
    save_report(repo_name, trivy_report, sonar_report, dependency_check_report)

if __name__ == "__main__":
    main()
