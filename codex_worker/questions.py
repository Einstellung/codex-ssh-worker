"""Private, per-job question exchange for a running Codex process."""
import re
import fcntl
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from .config import atomic_json, read_private

QUESTION_ID = re.compile(r"question_[a-f0-9]{24}\Z")


@contextmanager
def question_lock(path):
    with (Path(path) / "question.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def pending_question(path):
    path = Path(path)
    question = path / "question.json"
    if not question.is_file():
        return None
    data = read_private(question)
    identifier = data.get("question_id")
    if not isinstance(identifier, str) or not QUESTION_ID.fullmatch(identifier):
        raise ValueError("invalid question")
    if ((path / "answers" / (identifier + ".json")).exists()
            or (path / "closed-questions" / (identifier + ".json")).exists()):
        return None
    return data


def ask(path, question, timeout_seconds=900):
    """Block the internal tool, retaining the same Codex session and workspace."""
    path = Path(path)
    if not isinstance(question, str) or not 1 <= len(question.strip()) <= 4000:
        return {"error_code": "invalid_question"}
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 3600:
        return {"error_code": "invalid_question_timeout"}
    identifier = "question_" + uuid.uuid4().hex[:24]
    with question_lock(path):
        if pending_question(path):
            return {"error_code": "question_already_pending"}
        atomic_json(path / "question.json", {"question_id": identifier, "question": question})
    answer = path / "answers" / (identifier + ".json")
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if answer.is_file():
            return {"question_id": identifier, "answer": read_private(answer)["answer"]}
        if read_private(path / "state.json")["status"] != "running":
            return {"error_code": "task_not_running"}
        time.sleep(0.2)
    # Mark the question closed: a late answer must not be accepted.
    with question_lock(path):
        if answer.is_file():
            return {"question_id": identifier, "answer": read_private(answer)["answer"]}
        closed = path / "closed-questions"
        closed.mkdir(mode=0o700, exist_ok=True)
        atomic_json(closed / (identifier + ".json"), {"status": "timed_out"})
    return {"error_code": "question_timed_out"}
