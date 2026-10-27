import os
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.after_request
def identity(response):
    response.headers["X-Appsec-Lab-Identity"] = "fixture-flask-v1"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.get("/health")
def health():
    return jsonify(ready=True)


@app.get("/protected")
def protected():
    return (
        (jsonify(data="SYNTHETIC_PROTECTED"), 200)
        if request.headers.get("X-Test-User") == "alice"
        else (jsonify(error="authenticate"), 401)
    )


@app.get("/records/vulnerable/42")
def vulnerable():
    return (
        (jsonify(data="SYNTHETIC_ALICE_RECORD_42"), 200)
        if request.headers.get("X-Test-User")
        else (jsonify(error="authenticate"), 401)
    )


@app.get("/records/secure/42")
def secure():
    return (
        (jsonify(data="SYNTHETIC_ALICE_RECORD_42"), 200)
        if request.headers.get("X-Test-User") == "alice"
        else (jsonify(error="forbidden"), 403)
    )


@app.get("/validate")
def validate():
    value = request.args.get("id", "")
    return (
        (jsonify(valid=True), 200)
        if value.isdecimal() and len(value) <= 3
        else (jsonify(error="invalid id"), 400)
    )


if __name__ == "__main__":
    app.run(
        host="127.0.0.1", port=int(os.environ.get("PORT", "8765")), debug=False, use_reloader=False
    )
