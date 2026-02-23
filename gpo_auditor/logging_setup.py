"""Logging configuration for GPO Audit System."""

import os
import sys
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler

logger = None


def setup_logging(log_dir: str = 'logs', log_level: str = 'INFO',
                  console_level: str = 'WARNING', log_to_file: bool = True) -> logging.Logger:
    """Configure logging to console and file with rotation."""
    global logger

    if logger is not None:
        return logger

    if log_to_file and not os.path.exists(log_dir):
        os.makedirs(log_dir)

    logger = logging.getLogger('gpo_audit')
    logger.setLevel(logging.DEBUG)
    logger.handlers = []

    # Formatter
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    simple_formatter = logging.Formatter('%(levelname)s: %(message)s')

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, console_level.upper(), logging.WARNING))
    console_handler.setFormatter(simple_formatter)
    logger.addHandler(console_handler)

    # File handler
    if log_to_file:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        file_handler = RotatingFileHandler(
            os.path.join(log_dir, f'gpo_audit_{timestamp}.log'),
            maxBytes=5*1024*1024,
            backupCount=10,
            encoding='utf-8'
        )
        file_handler.setLevel(getattr(logging, log_level.upper(), logging.DEBUG))
        file_handler.setFormatter(detailed_formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger() -> logging.Logger:
    """Return logger instance, initialize if needed."""
    global logger
    if logger is None:
        logger = setup_logging()
    return logger
