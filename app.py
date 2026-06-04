import random

import base64
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

from db import fetch_message, fetch_metrics, insert_message, insert_eve_attempt
from orchestrator import hybrid_decrypt, hybrid_encrypt
from qkd_sim import binary_entropy, simulate_bb84

app = Flask(__name__)
CORS(app)


def compute_kgr(average_qber: float, average_sifted_bits: float) -> float:
    if average_qber >= 0.5:
        return 0.0
    return round(average_sifted_bits * (1 - binary_entropy(average_qber)), 2)


@app.route("/encrypt", methods=["POST"])
def encrypt_message():
    try:
        data = request.get_json()
        message = data.get("message") if isinstance(data, dict) else None
        if not isinstance(message, str) or not message.strip():
            return jsonify({"error": "message is required and must be non-empty"}), 400

        # Determine whether Eve is present this session:
        #   - If the caller explicitly sends eve_present: true, force Eve on.
        #   - Otherwise, 20% random chance (simulates real-world eavesdropping).
        if isinstance(data, dict) and data.get("eve_present") is True:
            eve_present = True
        else:
            eve_present = random.random() < 0.20

        try:
            result = hybrid_encrypt(message.strip(), eve_present=eve_present)
        except RuntimeError as exc:
            # QKD channel compromised — eavesdropping detected.
            # Run a standalone BB84 to get the actual QBER for the response.
            bb84_result = simulate_bb84(num_photons=5000, eve_present=True)
            real_qber = float(bb84_result["qber"])
            insert_eve_attempt(real_qber)
            return (
                jsonify(
                    {
                        "error": str(exc),
                        "qber": real_qber,
                        "channel_clean": False,
                    }
                ),
                422,
            )

        fields = {
            "encrypted_key": result["encrypted_key"],
            "ciphertext": result["ciphertext"],
            "nonce": result["nonce"],
            "tag": result["tag"],
            "key_id": result["key_id"],
            "qkd_key": base64.b64encode(result["qkd_key"]).decode("utf-8"),
            "qber": result["qber"],
            "sifted_bits": result["sifted_bits"],
        }

        uuid_str = insert_message(fields)

        return (
            jsonify(
                {
                    "uuid": uuid_str,
                    "encrypted_key": result["encrypted_key"],
                    "ciphertext": result["ciphertext"],
                    "nonce": result["nonce"],
                    "tag": result["tag"],
                    "key_id": result["key_id"],
                    "qber": result["qber"],
                    "channel_clean": True,
                }
            ),
            200,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/decrypt", methods=["POST"])
def decrypt_message():
    try:
        data = request.get_json()
        uuid_val = data.get("uuid") if isinstance(data, dict) else None
        if not isinstance(uuid_val, str) or not uuid_val.strip():
            return jsonify({"error": "uuid is required"}), 400

        row = fetch_message(uuid_val.strip())
        if row is None:
            return jsonify({"error": "Not found"}), 404

        qkd_key = base64.b64decode(row["qkd_key"])

        plaintext = hybrid_decrypt(
            row["encrypted_key"],
            row["ciphertext"],
            row["nonce"],
            row["tag"],
            qkd_key,
        )

        return jsonify({"message": plaintext}), 200
    except ValueError:
        return (
            jsonify(
                {"error": "Decryption failed: message may have been tampered with"}
            ),
            400,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/metrics", methods=["GET"])
def metrics():
    try:
        m = fetch_metrics()
        kgr = compute_kgr(float(m["average_qber"]), float(m["average_sifted_bits"]))
        return (
            jsonify(
                {
                    "total_messages": int(m["total_messages"]),
                    "average_qber": round(float(m["average_qber"]), 4),
                    "threats_detected": int(m["threats_detected"]),
                    "recent_qbers": m["recent_qbers"],
                    "kgr": kgr,
                }
            ),
            200,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/dashboard", methods=["GET"])
def dashboard():
    return render_template("dashboard.html")


@app.route("/channel", methods=["GET"])
def channel():
    return render_template("channel.html")


@app.route("/simulate-eve", methods=["POST"])
def simulate_eve():
    bb84_result = simulate_bb84(num_photons=1000, eve_present=True)
    real_qber = float(bb84_result["qber"])
    insert_eve_attempt(real_qber)
    try:
        hybrid_encrypt("eve test", eve_present=True)
    except RuntimeError:
        pass
    return (
        jsonify(
            {
                "channel_clean": False,
                "message": "Eavesdropping detected. Session aborted.",
                "qber": real_qber,
            }
        ),
        200,
    )


if __name__ == "__main__":
    app.run(debug=True)