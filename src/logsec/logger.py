import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import sys

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)

def setup_logging(log_dir="logs", log_file="logsec.log", max_bytes=10*1024*1024, backup_count=5):
    Path(log_dir).mkdir(exist_ok=True)
    log_path = Path(log_dir) / log_file
    
    logger = logging.getLogger("logsec")
    logger.setLevel(logging.DEBUG)
    
    file_handler = RotatingFileHandler(log_path, maxBytes=max_bytes, backupCount=backup_count)
    file_handler.setFormatter(JSONFormatter())
    logger.addHandler(file_handler)
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(JSONFormatter())
    logger.addHandler(console_handler)
    
    return logger
