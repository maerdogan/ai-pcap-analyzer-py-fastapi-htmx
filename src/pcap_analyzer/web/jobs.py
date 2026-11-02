"""Run analyses in the background, a few at a time."""
import shutil
import threading
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from .. import engine, knowledge, tshark

MAX_WAITING = 20


@dataclass
class Job:
    id: str
    filename: str
    state: str = "waiting"  # waiting, running, done, failed, cancelled
    analysis_id: str | None = None
    error: str | None = None
    language: str | None = None
    limit: tshark.Limit | None = None


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
            job = Job(uuid.uuid4().hex, filename, language=knowledge.language(), limit=tshark.Limit())
            self.jobs[job.id] = job
        self.pool.submit(self._run, job, tmpdir, capture, keylog, rsa_key, flt)
        return job

    def _run(self, job, tmpdir, capture, keylog, rsa_key, flt):
        knowledge.set_language(job.language)
        limit = job.limit
        try:
            limit.check()  # cancelled while waiting for a free slot
            job.state = "running"
            limit.start(self.settings.analysis_timeout_s)
            a = engine.analyze(capture, keylog, rsa_key, flt, self.settings, display_name=job.filename, limit=limit)
            job.analysis_id = a.id
            job.state = "done"
        except tshark.Stopped as e:
            job.state = "cancelled" if e.reason == "cancelled" else "failed"
            job.error = knowledge.t("The analysis passed its time limit of {n} seconds.", n=self.settings.analysis_timeout_s) if e.reason == "timeout" else None
        except (tshark.TsharkError, engine.CaptureTooLarge, ValueError, OSError) as e:
            job.error = str(e)
            job.state = "failed"
        except Exception:  # noqa: BLE001 - the page must show a failure, not spin forever
            traceback.print_exc()
            job.error = knowledge.t("The analysis stopped on an internal error. See the server log.")
            job.state = "failed"
        finally:
            limit.close()
            shutil.rmtree(tmpdir, ignore_errors=True)

    def cancel(self, jid):
        job = self.jobs.get(jid)
        if job and job.state in ("waiting", "running"):
            job.limit.stop()
        return job

    def get(self, jid):
        return self.jobs.get(jid)
