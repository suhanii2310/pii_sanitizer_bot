# RDA_BOTS/pii_sanitizer_bot/app.py
from flask import Flask, request, jsonify, send_from_directory
from pathlib import Path
import sys

# Make ../code importable
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "code"))

from pii_sanitizer import SanitizeBot  # uses existing bot


app = Flask(__name__, static_folder=str(ROOT / "frontend"), static_url_path="/")
bot = SanitizeBot(
    config={
        "default_action": "mask",
        "per_type": {
            "name": {"action": "tokenize"},
            "email": {"action": "tokenize"},
            "phone": {"action": "mask"},
            "ssn": {"action": "redact"},
            "credit_card": {"action": "mask"},
            "address": {"action": "mask"},
        },
        "column_hints": {  # helps avoid false positives on names
            "name": "name",
            "full_name": "name",
            "email": "email",
            "phone": "phone",
            "ssn": "ssn",
            "address": "address",
        },
        # "detect_names_in_free_text": True,  # enable if you want names detected in notes, too
    },
    hmac_secret="demo-key-change-me",
)


@app.route("/")
def index():
    # Serve the frontend
    return send_from_directory(app.static_folder, "index.html")


@app.post("/api/sanitize")
def api_sanitize():
    try:
        payload = request.get_json(force=True, silent=False) or {}
        input_data = payload.get("input_data", [])
        query_params = payload.get("query_params", {})
        # Always return audit to power the UI
        query_params["return_audit"] = True

        result = bot.bot_detect_and_sanitize(input_data=input_data, query_params=query_params)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    # pip install flask pandas (pandas is already used by the bot)
    app.run(host="127.0.0.1", port=5000, debug=True)
