#!/usr/bin/env python3
"""
Logging configuration for Cyber News Sender
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime

def setup_logger(name='cyber_news', log_level=logging.INFO):
    """Setup logger with file and console handlers."""
    
    # Determine log file path
    if os.path.exists('/app/data'):
        log_dir = '/app/data/logs'
    elif os.path.exists('data'):
        log_dir = 'data/logs'
    else:
        log_dir = 'logs'
    
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f'{name}.log')
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(log_level)
    
    # Remove existing handlers
    logger.handlers = []
    
    # File handler with rotation
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(log_level)
    file_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_format)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_format = logging.Formatter(
        '%(levelname)s: %(message)s'
    )
    console_handler.setFormatter(console_format)
    
    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

# Create default logger
logger = setup_logger()
