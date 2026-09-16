from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import joblib
import pandas as pd
from datetime import datetime

app = FastAPI(title="Real-Time Cybersecurity Threat Engine")
templates = Jinja2Templates(directory="templates")

# Load trained pipeline
model_pipeline = joblib.load("best_threat_model.pkl")

# In-memory database to store logs for the host dashboard
logs_db = []

class IncomingLog(BaseModel):
    user_agent: str
    request_path: str
    bytes_transferred: int
    response_code: int

@app.get("/", response_class=HTMLResponse)
def visitor_page(request: Request):
    """Serves the public visitor website."""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/owner-dashboard", response_class=HTMLResponse)
def owner_page(request: Request):
    """Serves the host security dashboard."""
    return templates.TemplateResponse("owner.html", {"request": request})

@app.post("/api/log-request")
def log_request(log: IncomingLog, request: Request):
    """Intercepts visitor requests, classifies threat level, and logs entry."""
    # Convert input payload to DataFrame matching training columns
    input_data = pd.DataFrame([{
        "user_agent": log.user_agent,
        "request_path": log.request_path,
        "bytes_transferred": log.bytes_transferred,
        "response_code": log.response_code
    }])

    # Run Prediction
    prediction = model_pipeline.predict(input_data)[0]
    
    # Map numeric prediction to threat status labels
    status_map = {0: "BENIGN", 1: "SUSPICIOUS", 2: "MALICIOUS"}
    label = status_map.get(prediction, "BENIGN")

    # Save entry to host database
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "client_ip": request.client.host if request.client else "127.0.0.1",
        "path": log.request_path,
        "user_agent": log.user_agent,
        "bytes": log.bytes_transferred,
        "code": log.response_code,
        "status": label
    }
    logs_db.insert(0, entry)  # Prepend latest entry

    return {"status": "SUCCESS", "threat_classification": label}

@app.get("/api/get-logs")
def get_logs():
    """Endpoint for Owner Dashboard to pull live visitor entries."""
    return {"logs": logs_db}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)