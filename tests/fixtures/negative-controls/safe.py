import subprocess


def run_fixed():
    return subprocess.run(["echo", "synthetic"], shell=False)


def lookup(db, resource_id):
    return db.execute("SELECT value FROM synthetic WHERE id = ?", (resource_id,))
