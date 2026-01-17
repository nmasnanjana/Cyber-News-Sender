#!/usr/bin/env python3
"""
Daily Email Sender Script
Sends daily cybersecurity news to all active subscribers at 9:30 AM IST
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.email_sender import CyberNewsEmailSender
from src.logger import logger
from src.analytics import Analytics

def main():
    """Send daily email to all active recipients from database."""
    try:
        logger.info("Starting daily email sending process")
        
        # Initialize email sender (uses database)
        sender = CyberNewsEmailSender(use_db=True)
        
        # Get articles from database (today's articles)
        articles_for_email = sender.db.get_recent_articles(days=1, limit=100)
        
        if not articles_for_email:
            logger.info("No articles found for today. Email not sent.")
            return
        
        logger.info(f"Found {len(articles_for_email)} articles to send")
        
        # Get active recipients from database
        recipients_list = sender.db.get_active_recipients()
        recipient_count = len(recipients_list)
        
        if recipient_count == 0:
            logger.warning("No active recipients found in database. Email not sent.")
            return
        
        logger.info(f"Found {recipient_count} active recipients in database")
        
        # Send email (recipients are fetched from database inside send_email)
        sender.send_email([a.to_dict() for a in articles_for_email])
        
        # Generate analytics
        try:
            analytics = Analytics()
            analytics.generate_daily_stats()
        except Exception as e:
            logger.error(f"Analytics failed: {e}")
        
        # Close database connection
        if sender.use_db:
            sender.db.close()
        
        logger.info("Daily email process completed successfully")
        
    except Exception as e:
        logger.error(f"Error in daily email process: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
