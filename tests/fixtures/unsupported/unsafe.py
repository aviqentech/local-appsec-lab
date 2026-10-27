import subprocess


def run_user_input(user_input):
    return subprocess.run(user_input, shell=True)
