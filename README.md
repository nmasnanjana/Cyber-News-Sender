# Cyber News Sender

Automated cybersecurity news aggregator with email distribution, web dashboard, CVE tracking, and analytics. Built with Python, Flask, MySQL, and Docker.

## Features

- **Automated News Scraping**: Scrapes cybersecurity news from 16+ RSS feeds every 6 hours
- **CVE Tracking**: Automatically extracts and validates CVE numbers, MITRE ATT&CK IDs
- **Email Distribution**: Sends daily digest emails to subscribers at 9:30 AM IST via BCC
- **Web Dashboard**: Modern web interface with analytics, charts, and article archive
- **MySQL Database**: Persistent storage with optimized queries and indexing
- **GDPR Compliant**: Data export, deletion, and consent management
- **Production Ready**: Gunicorn WSGI server, security headers, rate limiting

## Architecture

- **Backend**: Python 3.12, Flask, SQLAlchemy
- **Database**: MySQL 8.0
- **Web Server**: Gunicorn (production)
- **Containerization**: Docker & Docker Compose
- **Scheduling**: Cron jobs for scraping and email sending

## Prerequisites

- Docker and Docker Compose installed
- Port for web dashboard (default: 5000, configurable via `WEB_PORT` in `.env`)
- **Note**: MySQL database is not exposed externally - it's only accessible within the Docker network for security

## Quick Start

### 1. Clone the Repository

```bash
git clone <repository-url>
cd "Cyber News Sender"
```

### 2. Configure Environment

Copy the example environment file and update with your credentials:

```bash
cp config/.env.example config/.env
```

Edit `config/.env` with your settings:

```env
# MySQL Database Configuration
MYSQL_HOST=mysql
MYSQL_PORT=3306
MYSQL_USER=cybernews
MYSQL_PASSWORD=your_secure_mysql_password_here
MYSQL_DATABASE=cyber_news
MYSQL_ROOT_PASSWORD=your_secure_root_password_here

# Email Configuration
SMTP_SERVER=your_smtp_server
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USE_SSL=false
SENDER_EMAIL=your_email@domain.com
SENDER_PASSWORD=your_email_password
EMAIL_SUBJECT_PREFIX=Daily Cybersecurity News

# Application Configuration
TZ=Asia/Kolkata
PYTHONUNBUFFERED=1

# Web Dashboard Configuration
WEB_PORT=5000
```

### 3. Start Services

**Important**: Docker Compose needs to read the `.env` file for variable substitution. Use one of these methods:

**Option 1: Use --env-file flag (Recommended)**
```bash
docker compose --env-file config/.env up -d --build
```

**Option 2: Create a root-level .env file (Alternative)**
```bash
# Create a symlink or copy config/.env to root directory
ln -s config/.env .env
# Then run normally
docker compose up -d --build
```

**Option 3: Export variables before running**
```bash
export $(cat config/.env | grep -v '^#' | xargs)
docker compose up -d --build
```

This starts three services:
- **MySQL**: Database server
- **cyber-news**: Scraper with cron jobs
- **web-dashboard**: Web interface (port configurable via `WEB_PORT` in `.env`, default: 5000)

### 4. Access the Dashboard

Open your browser and navigate to:
```
http://localhost:5000
```

**Note**: If you changed the `WEB_PORT` in your `.env` file, use that port instead of 5000.

## Configuration

### Environment Variables

All configuration is managed through `config/.env`:

#### MySQL Configuration
- `MYSQL_HOST`: MySQL service name (default: `mysql`)
- `MYSQL_PORT`: MySQL port (default: `3306`)
- `MYSQL_USER`: Database user (default: `cybernews`)
- `MYSQL_PASSWORD`: Database password (required)
- `MYSQL_DATABASE`: Database name (default: `cyber_news`)
- `MYSQL_ROOT_PASSWORD`: MySQL root password (required)

#### Web Dashboard Configuration
- `WEB_PORT`: Port for the web dashboard (default: `5000`)
  - Change this if port 5000 is already in use
  - Update both the environment variable and ensure the port is available
  - Example: Set `WEB_PORT=8080` to use port 8080 instead

#### Email Configuration
- `SMTP_SERVER`: SMTP server hostname
- `SMTP_PORT`: SMTP port (default: `587`)
- `SMTP_USE_TLS`: Enable TLS (default: `true`)
- `SMTP_USE_SSL`: Use SSL instead of TLS (default: `false`)
- `SENDER_EMAIL`: Email address for sending
- `SENDER_PASSWORD`: Email account password
- `EMAIL_SUBJECT_PREFIX`: Email subject prefix

**Note**: Email recipients are managed through the web dashboard. Users subscribe via the "Subscribe" button, and their emails are stored in the MySQL database.

## Automated Tasks

### Scraping
- **Schedule**: Every 6 hours
- **Cron**: `0 */6 * * *`
- **Logs**: `/app/data/logs/scraper.log`
- **Function**: Scrapes RSS feeds, extracts CVEs, stores in database

### Email Sending
- **Schedule**: Daily at 9:30 AM IST (4:00 AM UTC)
- **Cron**: `0 4 * * *`
- **Logs**: `/app/data/logs/email.log`
- **Function**: Fetches active recipients from database, sends daily digest via BCC

## Project Structure

```
Cyber News Sender/
├── config/
│   ├── .env.example          # Environment variables template
│   └── .env                   # Your configuration (not in git)
├── src/
│   ├── __init__.py
│   ├── analytics.py           # Statistics and reporting
│   ├── article_scraper.py    # Article content extraction
│   ├── cve_extractor.py      # CVE and MITRE ATT&CK extraction
│   ├── cyber_news_scraper.py # Main RSS feed scraper
│   ├── database.py           # MySQL database models and operations
│   ├── email_sender.py       # Email sending functionality
│   ├── logger.py             # Logging configuration
│   ├── security.py           # Security utilities and GDPR compliance
│   ├── utils.py              # Common utility functions
│   └── web_app.py            # Flask web dashboard
├── data/
│   └── logs/                 # Application logs
├── docker-compose.yml        # Docker services configuration
├── Dockerfile                # Docker image definition
├── main.py                   # Scraper entry point
├── send_daily_email.py       # Email sending entry point
└── requirements.txt          # Python dependencies
```

## RSS Feeds

The application scrapes from the following sources:

- BleepingComputer
- ThreatPost
- The Hacker News
- The Cyber Express
- Cisco PSIRT, CSAF, Event Responses
- Palo Alto Networks
- AWS Security
- Google Security Blog
- Chrome Releases
- Cloudflare Changelog
- SANS ISC
- Krebs on Security
- Schneier on Security
- Kaspersky Securelist

## Web Dashboard Features

- **Dashboard**: Real-time statistics, charts, and today's articles
- **Archive**: Searchable archive with filtering (source, category, date)
- **Analytics**: Charts showing articles by source, category, time, and CVE distribution
- **Heatmaps**: Visual representation of top categories and CVEs
- **Subscribe**: Users can subscribe to daily emails via web interface

## Database Schema

### Tables
- **articles**: Scraped news articles with metadata
- **recipients**: Email subscribers
- **email_logs**: Email sending history
- **statistics**: Daily analytics data

## Security Features

- Input validation and sanitization
- SQL injection prevention (parameterized queries)
- XSS protection (HTML escaping)
- Rate limiting on API endpoints
- Security headers (CSP, X-Frame-Options, etc.)
- GDPR compliance (data export, deletion, consent)

## Monitoring

### Check Service Status
```bash
docker-compose ps
```

### View Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f cyber-news
docker-compose logs -f web-dashboard
docker-compose logs -f mysql

# Cron job logs
docker-compose exec cyber-news cat /app/data/logs/scraper.log
docker-compose exec cyber-news cat /app/data/logs/email.log
```

### Verify Cron Jobs
```bash
docker-compose exec cyber-news crontab -l
docker-compose exec cyber-news service cron status
```

## Troubleshooting

### Database Connection Issues
1. Verify MySQL container is running: `docker-compose ps`
2. Check MySQL logs: `docker-compose logs mysql`
3. Verify `.env` file has correct MySQL credentials
4. Wait for MySQL healthcheck to pass

### Email Not Sending
1. Check email logs: `docker-compose exec cyber-news cat /app/data/logs/email.log`
2. Verify SMTP credentials in `.env`
3. Check for active recipients: Access web dashboard and check subscribers
4. Test SMTP connection manually

### Web Dashboard Not Accessible
1. Check container status: `docker-compose ps web-dashboard`
2. View logs: `docker-compose logs web-dashboard`
3. Verify port 5000 is available: `netstat -tuln | grep 5000`
4. Check firewall rules

### Cron Jobs Not Running
1. Verify cron service: `docker-compose exec cyber-news service cron status`
2. Check cron configuration: `docker-compose exec cyber-news crontab -l`
3. View cron logs in container logs

## Testing Email Sending

### Manual Email Testing

Articles are marked as sent after successful email delivery to prevent duplicates. To test email sending manually, you need to reset the `last_sent_at` field.

#### Option 1: Using the Reset Script (Recommended)

A utility script is provided to easily reset articles for testing:

```bash
# Check current status
docker exec -it cyber-news-sender python3 /app/reset_articles_for_testing.py --status

# Reset today's articles (so they can be sent again)
docker exec -it cyber-news-sender python3 /app/reset_articles_for_testing.py --reset-today

# Reset a specific article by ID
docker exec -it cyber-news-sender python3 /app/reset_articles_for_testing.py --reset-id <ARTICLE_ID>

# Reset ALL articles (with confirmation prompt)
docker exec -it cyber-news-sender python3 /app/reset_articles_for_testing.py --reset-all
```

After resetting, run the email script:
```bash
docker exec -it cyber-news-sender python3 /app/send_daily_email.py
```

#### Option 2: Using SQL Commands

You can also reset articles directly via MySQL:

```bash
# Get MySQL password from your .env file first, then:
docker exec -it cyber-news-mysql mysql -u cybernews -p'YOUR_PASSWORD' cyber_news -e "UPDATE articles SET last_sent_at = NULL WHERE DATE(date) = CURDATE();"

# Or reset all articles
docker exec -it cyber-news-mysql mysql -u cybernews -p'YOUR_PASSWORD' cyber_news -e "UPDATE articles SET last_sent_at = NULL;"

# Check which articles are marked as sent
docker exec -it cyber-news-mysql mysql -u cybernews -p'YOUR_PASSWORD' cyber_news -e "SELECT id, title, last_sent_at FROM articles WHERE DATE(date) = CURDATE() ORDER BY id DESC LIMIT 10;"
```

**Note**: Replace `YOUR_PASSWORD` with your actual MySQL password from `config/.env`. If your password contains special characters, you may need to escape them or use the reset script instead.

## Development

### Running Locally (without Docker)

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set up MySQL database and configure `.env`

3. Run scraper:
```bash
python3 main.py
```

4. Run web dashboard:
```bash
python3 -m src.web_app
```

### Adding New RSS Feeds

Edit `src/cyber_news_scraper.py` and add a new scraping method following the existing pattern.
