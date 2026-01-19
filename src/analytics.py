#!/usr/bin/env python3
"""
Analytics and Reporting
"""

from .database import Database, Article, EmailLog, Statistic
from datetime import datetime, timedelta
import json
from .logger import logger

class Analytics:
    def __init__(self):
        self.db = Database()
    
    def generate_daily_stats(self):
        """Generate statistics for today."""
        try:
            # Use datetime boundaries (DateTime columns) to avoid MySQL date-vs-datetime coercion bugs
            today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
            
            # Articles scraped today
            articles_today = self.db.session.query(Article).filter(
                Article.created_at >= today_start
            ).count()
            
            # Articles sent today
            emails_today = self.db.session.query(EmailLog).filter(
                EmailLog.sent_at >= today_start
            ).all()
            articles_sent = sum(e.article_count for e in emails_today)
            
            # Unique CVEs today
            articles_with_cves = self.db.session.query(Article).filter(
                Article.created_at >= today_start,
                Article.cve_numbers.isnot(None)
            ).all()
            unique_cves = set()
            for article in articles_with_cves:
                if article.cve_numbers:
                    cves = json.loads(article.cve_numbers)
                    unique_cves.update(cves)
            
            # Source counts
            sources = {}
            articles = self.db.session.query(Article).filter(
                Article.created_at >= today_start
            ).all()
            for article in articles:
                sources[article.source] = sources.get(article.source, 0) + 1
            
            # Save statistics
            stat = Statistic(
                date=datetime.now(),
                articles_scraped=articles_today,
                articles_sent=articles_sent,
                unique_cves=len(unique_cves),
                sources_count=json.dumps(sources)
            )
            self.db.session.add(stat)
            self.db.session.commit()
            
            logger.info(f"Generated daily stats: {articles_today} articles, {len(unique_cves)} CVEs")
            
            return {
                'date': today_start.date().isoformat(),
                'articles_scraped': articles_today,
                'articles_sent': articles_sent,
                'unique_cves': len(unique_cves),
                'sources': sources
            }
        except Exception as e:
            logger.error(f"Error generating daily stats: {e}")
            return None
    
    def get_weekly_report(self):
        """Get weekly statistics."""
        try:
            week_ago = datetime.now() - timedelta(days=7)
            
            stats = self.db.session.query(Statistic).filter(
                Statistic.date >= week_ago
            ).order_by(Statistic.date.desc()).all()
            
            total_articles = sum(s.articles_scraped for s in stats)
            total_sent = sum(s.articles_sent for s in stats)
            total_cves = sum(s.unique_cves for s in stats)
            
            return {
                'period': '7 days',
                'total_articles': total_articles,
                'total_sent': total_sent,
                'total_cves': total_cves,
                'daily_breakdown': [s.to_dict() for s in stats]
            }
        except Exception as e:
            logger.error(f"Error generating weekly report: {e}")
            return None
    
    def get_top_cves(self, limit=10):
        """Get most mentioned CVEs."""
        try:
            all_articles = self.db.session.query(Article).filter(
                Article.cve_numbers.isnot(None)
            ).all()
            
            cve_counts = {}
            for article in all_articles:
                if article.cve_numbers:
                    cves = json.loads(article.cve_numbers)
                    for cve in cves:
                        cve_counts[cve] = cve_counts.get(cve, 0) + 1
            
            top_cves = sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
            
            return [{'cve': cve, 'count': count} for cve, count in top_cves]
        except Exception as e:
            logger.error(f"Error getting top CVEs: {e}")
            return []

# This is a module - use main.py as entry point
