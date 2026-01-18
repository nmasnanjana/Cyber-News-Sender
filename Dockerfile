FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies including cron
RUN apt-get update && apt-get install -y \
    gcc \
    cron \
    default-libmysqlclient-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ /app/src/
COPY main.py .
COPY send_daily_email.py .
COPY reset_articles_for_testing.py .
COPY config/ /app/config/

# Create directories for logs only (no data directory needed with MySQL)
RUN mkdir -p /app/data/logs

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV TZ=Asia/Kolkata

# Setup cron jobs
# 1. Scraping: runs every 6 hours
# 2. Email sending: runs daily at 9:30 AM IST (4:00 AM UTC)
RUN echo "0 */6 * * * cd /app && /usr/local/bin/python3 main.py >> /app/data/logs/scraper.log 2>&1" > /etc/cron.d/cyber-news-scraper && \
    echo "0 4 * * * cd /app && /usr/local/bin/python3 send_daily_email.py >> /app/data/logs/email.log 2>&1" >> /etc/cron.d/cyber-news-scraper && \
    chmod 0644 /etc/cron.d/cyber-news-scraper && \
    crontab /etc/cron.d/cyber-news-scraper

# Create entrypoint script
RUN echo '#!/bin/bash\n\
set -e\n\
# Start cron\n\
service cron start\n\
# Keep container running\n\
tail -f /dev/null' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Run entrypoint
CMD ["/app/entrypoint.sh"]
