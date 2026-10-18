import logging
import sys
from .config import settings
from .queue import WorkerDaemon

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )

def main():
    setup_logging()
    daemon = WorkerDaemon()
    daemon.start()

if __name__ == "__main__":
    main()
