from flask import Flask, request, jsonify
from flask_cors import CORS
from scanner import perform_static_scan

# 1. Initialize Flask app FIRST
app = Flask(__name__)
CORS(app)  # Enable CORS for frontend connectivity

@app.route("/")
def health_check():
    return jsonify({"status": "online", "service": "AI Security Guard API"})

@app.route("/api/scan", methods=["POST"])
def scan_code():
    data = request.get_json()
    if not data or "code" not in data or not data["code"].strip():
        return jsonify({"error": "Code snippet cannot be empty."}), 400
    
    code = data["code"]
    language = data.get("language", "python")
    
    # Run static regex & syntax checker
    static_issues = perform_static_scan(code, language)
    
    # Calculate baseline risk score
    risk_score = min(100, len(static_issues) * 25)
    if risk_score == 0 and len(code) > 0:
        risk_score = 5 # Clean baseline
        
    return jsonify({
        "status": "success",
        "summary": {
            "total_issues": len(static_issues),
            "risk_score": risk_score,
            "status_label": "CRITICAL RISK" if risk_score >= 75 else "MODERATE RISK" if risk_score >= 30 else "SECURE"
        },
        "vulnerabilities": static_issues
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)