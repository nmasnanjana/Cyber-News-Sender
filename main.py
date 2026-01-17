#!/usr/bin/env python3
"""
Main entry point for Cyber News Sender
Runs scraper and email sender
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.cyber_news_scraper import CyberNewsScraper
from src.email_sender import CyberNewsEmailSender
from src.logger import logger
from src.analytics import Analytics

def main():
    """Main function to run scraper and send email."""
    try:
        # Run scraper
        logger.info("Starting daily cyber news process")
        scraper = CyberNewsScraper(max_age_days=3, use_db=True)
        articles = scraper.scrape_all()
        
        if articles:
            logger.info(f"Found {len(articles)} new articles")
            
            # Generate analytics
            try:
                analytics = Analytics()
                analytics.generate_daily_stats()
            except Exception as e:
                logger.error(f"Analytics failed: {e}")
            
            # Note: Email sending is handled separately by send_daily_email.py cron job at 9:30 AM IST
            # This script only handles scraping
            
            # Close database connections
            if scraper.use_db:
                scraper.db.close()
        else:
            logger.info("No new articles found")
        
        logger.info("Daily process completed")
        
    except Exception as e:
        logger.error(f"Error in main process: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
