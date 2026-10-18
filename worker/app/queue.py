import logging
import signal
import sys
import threading
import time
from .config import settings
from .db import claim_job, heartbeat_job
from .runner import execute_scan_job

logger = logging.getLogger("reversebug.worker.queue")

class WorkerDaemon:
    def __init__(self):
        self.stop_requested = False
        self.active_job_id = None
        self.heartbeat_thread = None

    def start(self):
        logger.info("Initializing ReverseBug Worker Daemon [ID: %s]", settings.worker_id)
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

        while not self.stop_requested:
            try:
                job = claim_job(settings.worker_id)
                if job:
                    self._process_job(job)
                else:
                    time.sleep(settings.poll_interval_seconds)
            except Exception as e:
                logger.error("Error in queue processing loop: %s", e)
                time.sleep(settings.poll_interval_seconds)

        logger.info("Worker daemon stopped gracefully.")

    def _process_job(self, job):
        self.active_job_id = job["id"]
        stop_heartbeat = threading.Event()

        def heartbeat_loop():
            while not stop_heartbeat.wait(settings.heartbeat_interval_seconds):
                try:
                    heartbeat_job(job["id"], settings.worker_id)
                except Exception as e:
                    logger.warning("Heartbeat failed for job %s: %s", job["id"], e)

        hb_thread = threading.Thread(target=heartbeat_loop, daemon=True)
        hb_thread.start()

        try:
            execute_scan_job(job)
        finally:
            stop_heartbeat.set()
            hb_thread.join(timeout=2.0)
            self.active_job_id = None

    def _handle_signal(self, signum, frame):
        logger.info("Shutdown signal received (%s), draining active jobs...", signum)
        self.stop_requested = True
