#!/usr/bin/env python3
"""
Utility script to reset articles for email testing
Resets last_sent_at field so articles can be sent again
"""

import sys
import os
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.database import Database
from src.logger import logger

def reset_articles_for_today():
    """Reset last_sent_at for all articles from today."""
    try:
        db = Database()
        
        today_date = datetime.utcnow().date()
        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        
        # Count articles that will be reset
        from src.database import Article
        count = db.session.query(Article).filter(
            Article.date >= today_date,
            Article.last_sent_at.isnot(None)
        ).count()
        
        if count == 0:
            print("No articles found with last_sent_at set for today.")
            return
        
        print(f"Found {count} articles to reset for today ({today_date})")
        
        # Reset last_sent_at
        updated = db.session.query(Article).filter(
            Article.date >= today_date,
            Article.last_sent_at.isnot(None)
        ).update(
            {Article.last_sent_at: None},
            synchronize_session=False
        )
        db.session.commit()
        
        print(f"✓ Successfully reset {updated} articles. They can now be sent again.")
        logger.info(f"Reset {updated} articles for testing")
        
        db.close()
        
    except Exception as e:
        logger.error(f"Error resetting articles: {e}")
        print(f"✗ Error: {e}")
        sys.exit(1)

def reset_all_articles():
    """Reset last_sent_at for ALL articles (use with caution)."""
    try:
        db = Database()
        
        from src.database import Article
        count = db.session.query(Article).filter(
            Article.last_sent_at.isnot(None)
        ).count()
        
        if count == 0:
            print("No articles found with last_sent_at set.")
            return
        
        print(f"Found {count} articles to reset (ALL articles)")
        response = input("Are you sure you want to reset ALL articles? (yes/no): ")
        
        if response.lower() != 'yes':
            print("Cancelled.")
            return
        
        # Reset last_sent_at
        updated = db.session.query(Article).filter(
            Article.last_sent_at.isnot(None)
        ).update(
            {Article.last_sent_at: None},
            synchronize_session=False
        )
        db.session.commit()
        
        print(f"✓ Successfully reset {updated} articles.")
        logger.info(f"Reset {updated} articles for testing (all articles)")
        
        db.close()
        
    except Exception as e:
        logger.error(f"Error resetting articles: {e}")
        print(f"✗ Error: {e}")
        sys.exit(1)

def reset_specific_article(article_id):
    """Reset last_sent_at for a specific article by ID."""
    try:
        db = Database()
        
        from src.database import Article
        article = db.session.query(Article).filter_by(id=article_id).first()
        
        if not article:
            print(f"Article with ID {article_id} not found.")
            return
        
        if article.last_sent_at is None:
            print(f"Article {article_id} ({article.title[:50]}...) is not marked as sent.")
            return
        
        article.last_sent_at = None
        db.session.commit()
        
        print(f"✓ Successfully reset article {article_id}: {article.title[:50]}...")
        logger.info(f"Reset article {article_id} for testing")
        
        db.close()
        
    except Exception as e:
        logger.error(f"Error resetting article: {e}")
        print(f"✗ Error: {e}")
        sys.exit(1)

def show_status():
    """Show status of articles for today."""
    try:
        db = Database()
        
        from src.database import Article
        today_date = datetime.utcnow().date()
        
        total = db.session.query(Article).filter(Article.date >= today_date).count()
        sent = db.session.query(Article).filter(
            Article.date >= today_date,
            Article.last_sent_at.isnot(None)
        ).count()
        unsent = total - sent
        
        print(f"\nArticle Status for Today ({today_date}):")
        print(f"  Total articles: {total}")
        print(f"  Already sent: {sent}")
        print(f"  Not sent yet: {unsent}")
        
        if sent > 0:
            print(f"\nTo reset sent articles for testing, run:")
            print(f"  python3 reset_articles_for_testing.py --reset-today")
        
        db.close()
        
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        print(f"✗ Error: {e}")
        sys.exit(1)

def main():
    """Main function."""
    if len(sys.argv) > 1:
        if sys.argv[1] == '--reset-today':
            reset_articles_for_today()
        elif sys.argv[1] == '--reset-all':
            reset_all_articles()
        elif sys.argv[1] == '--reset-id' and len(sys.argv) > 2:
            try:
                article_id = int(sys.argv[2])
                reset_specific_article(article_id)
            except ValueError:
                print("Error: Article ID must be a number")
                sys.exit(1)
        elif sys.argv[1] == '--status':
            show_status()
        else:
            print("Usage:")
            print("  python3 reset_articles_for_testing.py --status          # Show article status")
            print("  python3 reset_articles_for_testing.py --reset-today      # Reset today's articles")
            print("  python3 reset_articles_for_testing.py --reset-all        # Reset ALL articles (with confirmation)")
            print("  python3 reset_articles_for_testing.py --reset-id <ID>    # Reset specific article by ID")
    else:
        show_status()

if __name__ == "__main__":
    main()
