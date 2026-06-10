import json
import logging
from logging.handlers import RotatingFileHandler

class LogsecFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": self.formatTime(record, "%Y-%m-%d %H:%M:%S"),
            "level": record.levelname,
            "message": record.getMessage(),
            "metadata": {}
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)

def setup_logging():
    logger = logging.getLogger("logsec")
    logger.setLevel(logging.DEBUG)

    handler = RotatingFileHandler('logs/logsec.log', maxBytes=1024*1024*5, backupCount=3)
    handler.setFormatter(LogsecFormatter())

    logger.addHandler(handler)
    return logger
