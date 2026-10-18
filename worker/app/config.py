import os
import socket
from pathlib import Path
from pydantic import BaseModel

class Config(BaseModel):
    env: str = os.getenv("RB_ENV", "development")
    database_url: str = os.getenv(
        "RB_DATABASE_URL",
        "postgres://reversebug:reversebug_dev_password@127.0.0.1:5433/reversebug?sslmode=disable"
    )
    storage_dir: Path = Path(os.getenv("RB_STORAGE_DIR", "../api/data/storage")).resolve()
    worker_id: str = f"worker-{socket.gethostname()}-{os.getpid()}"
    poll_interval_seconds: float = float(os.getenv("RB_WORKER_POLL_INTERVAL", "2.0"))
    heartbeat_interval_seconds: float = float(os.getenv("RB_WORKER_HEARTBEAT_INTERVAL", "15.0"))
    batch_size: int = 1

settings = Config()
