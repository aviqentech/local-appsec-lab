from local_appsec_lab.discovery import inspect
from local_appsec_lab.intelligence.dataflow import analyze


def test_cross_module_request_to_sql_and_bound_negative_control(tmp_path):
    (tmp_path / "db.py").write_text(
        'def unsafe(cursor, value):\n    sql = "SELECT * FROM records WHERE id=" + value\n    cursor.execute(sql)\n\ndef safe(cursor, value):\n    cursor.execute("SELECT * FROM records WHERE id=?", (value,))\n'
    )
    (tmp_path / "app.py").write_text(
        'from db import unsafe, safe\n@app.route("/records")\ndef records():\n    user_input = request.args.get("id")\n    unsafe(cursor, user_input)\n    safe(cursor, user_input)\n'
    )
    findings, checks = analyze(tmp_path, inspect(tmp_path))
    assert (
        len(findings) == 1 and findings[0].source.path == "db.py" and findings[0].source.line == 3
    )
    assert findings[0].evidence[0]["sources"] == ["app.py:4:request-input"]
    assert checks[0].status == "completed" and findings[0].state == "candidate"


def test_taint_killed_by_constant_and_return_flow(tmp_path):
    (tmp_path / "app.py").write_text(
        'def forward(value):\n    return value\n@app.get("/go")\ndef go():\n    value = forward(request.args.get("q"))\n    eval(value)\n    value = "constant"\n    eval(value)\n'
    )
    findings, _ = analyze(tmp_path, inspect(tmp_path))
    assert len(findings) == 1 and findings[0].source.line == 6
