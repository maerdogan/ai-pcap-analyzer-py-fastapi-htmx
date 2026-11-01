"""Run analyses in the background, a few at a time."""
import shutil
import threading
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from .. import engine, tshark

MAX_WAITING = 20


@dataclass
class Job:
    id: str
    filename: str
    state: str = "waiting"  # waiting, running, done, failed
    analysis_id: str | None = None
    error: str | None = None


class QueueFull(Exception):
    pass


class Jobs:
    def __init__(self, settings):
        self.settings = settings
        self.pool = ThreadPoolExecutor(max_workers=settings.max_jobs, thread_name_prefix="analysis")
        self.jobs = {}
        self.lock = threading.Lock()

    def submit(self, tmpdir, capture, filename, keylog, rsa_key, flt):
        with self.lock:
            if sum(j.state in ("waiting", "running") for j in self.jobs.values()) >= MAX_WAITING:
                raise QueueFull
            job = Job(uuid.uuid4().hex, filename)
            self.jobs[job.id] = job
        self.pool.submit(self._run, job, tmpdir, capture, keylog, rsa_key, flt)
        return job

    def _run(self, job, tmpdir, capture, keylog, rsa_key, flt):
        job.state = "running"
        try:
            a = engine.analyze(capture, keylog, rsa_key, flt, self.settings, display_name=job.filename)
            job.analysis_id = a.id
            job.state = "done"
        except (tshark.TsharkError, engine.CaptureTooLarge, ValueError, OSError) as e:
            job.error = str(e)
            job.state = "failed"
        except Exception:  # noqa: BLE001 - the page must show a failure, not spin forever
            traceback.print_exc()
            job.error = "The analysis stopped on an internal error. See the server log."
            job.state = "failed"
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def get(self, jid):
        return self.jobs.get(jid)
