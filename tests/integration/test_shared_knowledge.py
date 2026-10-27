from local_appsec_lab.agents.knowledge import SharedKnowledge
from local_appsec_lab.discovery import inspect
from local_appsec_lab.findings import RunStore
from local_appsec_lab.models import Check


def test_worker_context_is_detached_and_history_append_only(tmp_path):
    (tmp_path / "app.py").write_text("value = 1\n")
    store = RunStore(tmp_path / ".appsec-lab")
    try:
        shared = SharedKnowledge(store, "synthetic-knowledge", inspect(tmp_path))
        first = shared.context([])
        first["architecture"]["languages"].append("worker-forgery")
        assert "worker-forgery" not in shared.context([])["architecture"]["languages"]
        shared.publish(
            "deterministic", [], [Check(id="control", category="validation", status="completed")]
        )
        assert shared.context([])["revision"] == 2
        assert shared.value.completed_checks[0]["id"] == "control"
    finally:
        store.close()
