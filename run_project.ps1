# run_project.ps1

# 1. DEFINE PATHS
$ProjectRoot = Get-Item -Path $PSScriptRoot
$VenvPath = Join-Path $ProjectRoot "venv\Scripts\activate.ps1"

# 2. ACTIVATE VIRTUAL ENVIRONMENT
Write-Host "Activating virtual environment..."
if (Test-Path $VenvPath) {
    # The dot source operator (.) runs the script in the current scope
    . $VenvPath
    if (!$LASTEXITCODE -ne 0) {
        Write-Error "Failed to activate virtual environment."
        exit 1
    }
} else {
    Write-Error "Virtual environment not found at $VenvPath. Please run 'python -m venv venv' first."
    exit 1
}

# 3. SET FLASK APP VARIABLE (FLASK_APP is not a secret, so it's safe here)
$env:FLASK_APP="photos.py"

# 4. RUN FLASK APPLICATION
Write-Host "Starting Flask development server..."
# NOTE: The AZURE_STORAGE_CONNECTION_STRING is now loaded by python-dotenv 
# inside photos.py, so it does NOT need to be set here.
flask run

# --- END OF SCRIPT ---