"""PhishGuard AI API service. Deploy this folder to a Python host (e.g. Render)."""
import os
import csv
import io
import re
from flask import Flask, request, jsonify
import detector

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB request limit


def allowed_origins():
    raw = os.environ.get("PHISHGUARD_ALLOWED_ORIGINS", "*").strip()
    return ["*"] if raw == "*" else [x.strip() for x in raw.split(",") if x.strip()]


@app.after_request
def add_cors(response):
    origin = request.headers.get("Origin", "")
    allowed = allowed_origins()
    if "*" in allowed:
        response.headers["Access-Control-Allow-Origin"] = "*"
    elif origin in allowed:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers.add("Vary", "Origin")
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Max-Age"] = "600"
    return response


@app.errorhandler(413)
def too_large(_error):
    return jsonify({"error": "Upload is too large. Maximum request size is 2 MB."}), 413


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "PhishGuard AI API"})


@app.route("/api/analyze", methods=["POST", "OPTIONS"])
def api_analyze():
    if request.method == "OPTIONS":
        return ("", 204)
    data = request.get_json(silent=True) or {}
    text = str(data.get("text", "")).strip()
    if not text:
        return jsonify({"error": "Empty email"}), 400
    if len(text) > 1_000_000:
        return jsonify({"error": "Email text is too long (maximum 1 MB)."}), 413
    return jsonify(detector.analyze(text))


@app.route("/api/batch", methods=["POST", "OPTIONS"])
def api_batch():
    if request.method == "OPTIONS":
        return ("", 204)
    data = request.get_json(silent=True) or {}
    raw = str(data.get("text", ""))
    chunks = [c.strip() for c in re.split(r"\n\s*={2,}\s*\n", raw) if c.strip()]
    if not chunks:
        return jsonify({"error": "No emails supplied"}), 400
    if len(chunks) > 100:
        return jsonify({"error": "Maximum 100 emails per batch."}), 400
    out = []
    for i, chunk in enumerate(chunks, 1):
        result = detector.analyze(chunk)
        out.append({"index": i, "score": result["score"],
                    "verdict": result["final_verdict"],
                    "ai_prob": result.get("ai_prob")})
    return jsonify({"results": out, "total": len(out)})


@app.route("/api/ai_status", methods=["GET"])
def api_ai_status():
    ready = detector.load_or_train()
    return jsonify({"ai_ready": ready, "model_loaded": detector._MODEL is not None})


@app.route("/api/retrain", methods=["POST", "OPTIONS"])
def api_retrain():
    if request.method == "OPTIONS":
        return ("", 204)
    pkl = os.path.join(os.path.dirname(os.path.abspath(detector.__file__)), "model.pkl")
    if os.path.exists(pkl):
        os.remove(pkl)
    detector._MODEL = None
    detector._MODEL_READY = False
    return jsonify({"retrained": detector.load_or_train()})


@app.route("/api/upload_csv", methods=["POST", "OPTIONS"])
def api_upload_csv():
    if request.method == "OPTIONS":
        return ("", 204)
    uploaded = request.files.get("file")
    if not uploaded:
        return jsonify({"error": "No file uploaded"}), 400
    try:
        rows = list(csv.reader(io.StringIO(uploaded.read().decode("utf-8-sig", errors="ignore"))))
        if len(rows) < 2:
            return jsonify({"error": "CSV must contain a header and at least one row."}), 400
        headers = [h.strip().lower() for h in rows[0]]
        text_col = next((i for i, h in enumerate(headers)
                         if any(k in h for k in ("text", "email", "body", "message", "content"))), None)
        if text_col is None:
            return jsonify({"error": "Could not find email/text column"}), 400
        out = []
        for idx, row in enumerate(rows[1:], 1):
            if len(row) <= text_col or not row[text_col].strip():
                continue
            result = detector.analyze(row[text_col])
            out.append({"index": idx, "score": result["score"],
                        "verdict": result["final_verdict"],
                        "ai_prob": result.get("ai_prob")})
            if len(out) >= 100:
                break
        return jsonify({"results": out, "total": len(out)})
    except Exception:
        app.logger.exception("CSV processing failed")
        return jsonify({"error": "Could not process this CSV file."}), 400


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
