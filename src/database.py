#!/usr/bin/env python3
"""
Database models and operations for Cyber News Sender
"""

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, Float, text, Index, bindparam
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta
import os
import json
import logging
from contextlib import contextmanager
from .utils import get_content_hash, normalize_url, sanitize_string

logger = logging.getLogger('cyber_news')

Base = declarative_base()

class Article(Base):
    __tablename__ = 'articles'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(500), nullable=False)
    url = Column(String(1000), nullable=False)  # Removed unique constraint, using content_hash for uniqueness
    source = Column(String(100), nullable=False)
    date = Column(DateTime, index=True)
    content_hash = Column(String(64), unique=True, nullable=False, index=True)
    cve_numbers = Column(Text)  # JSON array of CVE numbers
    mitre_attack_ids = Column(Text)  # JSON array of MITRE ATT&CK technique IDs
    categories = Column(Text)  # JSON array of categories
    keywords = Column(Text)  # JSON array of keywords
    summary = Column(Text)  # Article summary
    content = Column(Text)  # Full article content
    cve_details = Column(Text)  # JSON object with CVE details
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    last_sent_at = Column(DateTime, nullable=True, index=True)  # Track when article was last sent via email
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'url': self.url,
            'source': self.source,
            'date': self.date.isoformat() if self.date else None,
            'cve_numbers': json.loads(self.cve_numbers) if self.cve_numbers else [],
            'mitre_attack_ids': json.loads(self.mitre_attack_ids) if self.mitre_attack_ids else [],
            'categories': json.loads(self.categories) if self.categories else [],
            'keywords': json.loads(self.keywords) if self.keywords else [],
            'summary': self.summary,
            'content': self.content,
            'cve_details': json.loads(self.cve_details) if self.cve_details else {},
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_sent_at': self.last_sent_at.isoformat() if self.last_sent_at else None
        }

# Create indexes for performance
# Note: URL index is created with prefix (255 chars) in _create_indexes() to avoid MySQL key length limit
Index('idx_articles_date', Article.date)
Index('idx_articles_source', Article.source)
# Index('idx_articles_url', Article.url)  # Created manually with prefix in _create_indexes()
Index('idx_articles_content_hash', Article.content_hash)
Index('idx_articles_last_sent_at', Article.last_sent_at)

class Recipient(Base):
    __tablename__ = 'recipients'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(100))
    active = Column(Boolean, default=True, index=True)
    preferences = Column(Text)  # JSON object with preferences
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'active': self.active,
            'preferences': json.loads(self.preferences) if self.preferences else {},
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class EmailLog(Base):
    __tablename__ = 'email_logs'
    
    id = Column(Integer, primary_key=True)
    sent_at = Column(DateTime, default=datetime.utcnow)
    article_count = Column(Integer, default=0)
    recipient_count = Column(Integer, default=0)
    success = Column(Boolean, default=True)
    error_message = Column(Text)
    
    def to_dict(self):
        return {
            'id': self.id,
            'sent_at': self.sent_at.isoformat() if self.sent_at else None,
            'article_count': self.article_count,
            'recipient_count': self.recipient_count,
            'success': self.success,
            'error_message': self.error_message
        }

class Statistic(Base):
    __tablename__ = 'statistics'
    
    id = Column(Integer, primary_key=True)
    date = Column(DateTime, default=datetime.utcnow)
    articles_scraped = Column(Integer, default=0)
    articles_sent = Column(Integer, default=0)
    unique_cves = Column(Integer, default=0)
    sources_count = Column(Text)  # JSON object with source counts
    
    def to_dict(self):
        return {
            'id': self.id,
            'date': self.date.isoformat() if self.date else None,
            'articles_scraped': self.articles_scraped,
            'articles_sent': self.articles_sent,
            'unique_cves': self.unique_cves,
            'sources_count': json.loads(self.sources_count) if self.sources_count else {}
        }

class Database:
    def __init__(self, db_path=None):
        # Get MySQL connection details from environment variables
        mysql_host = os.getenv('MYSQL_HOST', 'mysql')
        mysql_port = int(os.getenv('MYSQL_PORT', '3306'))
        mysql_user = os.getenv('MYSQL_USER', 'cybernews')
        mysql_password = os.getenv('MYSQL_PASSWORD', '')
        mysql_database = os.getenv('MYSQL_DATABASE', 'cyber_news')
        
        # Validate required MySQL credentials
        if not mysql_password:
            raise ValueError("MYSQL_PASSWORD environment variable is required")
        
        # Construct MySQL connection string
        # Use pymysql as the driver
        mysql_url = f"mysql+pymysql://{mysql_user}:{mysql_password}@{mysql_host}:{mysql_port}/{mysql_database}?charset=utf8mb4"
        
        # Configure MySQL connection with connection pooling
        self.engine = create_engine(
            mysql_url,
            echo=False,
            pool_pre_ping=True,  # Verify connections before using
            pool_size=10,  # Connection pool size
            max_overflow=20,  # Maximum overflow connections
            pool_recycle=3600,  # Recycle connections after 1 hour
            connect_args={
                'connect_timeout': 10
            }
        )
        
        # Create database if it doesn't exist (MySQL handles this automatically via docker-compose)
        # Create all tables
        Base.metadata.create_all(self.engine)
        self._migrate_database()
        self._create_indexes()
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
    
    def _migrate_database(self):
        """Migrate database schema to add new columns if they don't exist (MySQL)."""
        try:
            with self.engine.connect() as conn:
                # Check if columns exist in MySQL
                result = conn.execute(text("""
                    SELECT COLUMN_NAME 
                    FROM INFORMATION_SCHEMA.COLUMNS 
                    WHERE TABLE_SCHEMA = DATABASE() 
                    AND TABLE_NAME = 'articles'
                """))
                columns = [row[0] for row in result]
                
                # Add missing columns (MySQL syntax)
                if 'summary' not in columns:
                    conn.execute(text("ALTER TABLE articles ADD COLUMN summary TEXT"))
                    conn.commit()
                    logger.info("Added 'summary' column to articles table")
                
                if 'content' not in columns:
                    conn.execute(text("ALTER TABLE articles ADD COLUMN content TEXT"))
                    conn.commit()
                    logger.info("Added 'content' column to articles table")
                
                if 'cve_details' not in columns:
                    conn.execute(text("ALTER TABLE articles ADD COLUMN cve_details TEXT"))
                    conn.commit()
                    logger.info("Added 'cve_details' column to articles table")
                
                if 'mitre_attack_ids' not in columns:
                    conn.execute(text("ALTER TABLE articles ADD COLUMN mitre_attack_ids TEXT"))
                    conn.commit()
                    logger.info("Added 'mitre_attack_ids' column to articles table")
                
                if 'last_sent_at' not in columns:
                    conn.execute(text("ALTER TABLE articles ADD COLUMN last_sent_at DATETIME NULL"))
                    conn.commit()
                    logger.info("Added 'last_sent_at' column to articles table")
        except Exception as e:
            # If migration fails, log but don't crash
            logger.warning(f"Database migration warning: {e}")
            # Try to continue anyway
    
    def _create_indexes(self):
        """Create indexes for better query performance (MySQL)."""
        try:
            with self.engine.connect() as conn:
                # Check existing indexes in MySQL
                result = conn.execute(text("""
                    SELECT INDEX_NAME 
                    FROM INFORMATION_SCHEMA.STATISTICS 
                    WHERE TABLE_SCHEMA = DATABASE() 
                    AND TABLE_NAME = 'articles' 
                    AND INDEX_NAME LIKE 'idx_%'
                """))
                existing_indexes = [row[0] for row in result]
                
                # Create indexes if they don't exist (MySQL syntax)
                # Wrap each in try-except to handle race conditions and duplicate key errors gracefully
                index_creations = [
                    ('idx_articles_date', "CREATE INDEX idx_articles_date ON articles(date)"),
                    ('idx_articles_source', "CREATE INDEX idx_articles_source ON articles(source)"),
                    ('idx_articles_url', "CREATE INDEX idx_articles_url ON articles(url(255))"),
                    ('idx_articles_content_hash', "CREATE INDEX idx_articles_content_hash ON articles(content_hash)"),
                    ('idx_articles_last_sent_at', "CREATE INDEX idx_articles_last_sent_at ON articles(last_sent_at)")
                ]
                
                for index_name, create_sql in index_creations:
                    if index_name not in existing_indexes:
                        try:
                            conn.execute(text(create_sql))
                            conn.commit()
                        except Exception as idx_error:
                            # Ignore duplicate key errors (1061) - index might have been created by another process
                            error_str = str(idx_error)
                            if '1061' in error_str or 'Duplicate key name' in error_str:
                                # Index already exists, ignore
                                pass
                            else:
                                logger.warning(f"Index creation warning for {index_name}: {idx_error}")
        except Exception as e:
            # Only log if it's not a duplicate key error
            error_str = str(e)
            if '1061' not in error_str and 'Duplicate key name' not in error_str:
                logger.warning(f"Index creation warning: {e}")
    
    def get_content_hash(self, url, title):
        """Generate hash for duplicate detection."""
        return get_content_hash(url, title)
    
    def article_exists(self, url, title):
        """Check if article already exists."""
        content_hash = self.get_content_hash(url, title)
        return self.session.query(Article).filter_by(content_hash=content_hash).first() is not None
    
    def articles_exist_bulk(self, content_hashes):
        """Check which articles exist from a list of content hashes (bulk operation)."""
        if not content_hashes:
            return set()
        existing = self.session.query(Article.content_hash).filter(
            Article.content_hash.in_(content_hashes)
        ).all()
        return {row[0] for row in existing}
    
    def add_article(self, title, url, source, date=None, cve_numbers=None, mitre_attack_ids=None, categories=None, keywords=None, summary=None, content=None, cve_details=None):
        """Add article to database with input validation."""
        # Validate and sanitize inputs
        title = sanitize_string(title, max_length=500)
        url = normalize_url(url)
        source = sanitize_string(source, max_length=100)
        summary = sanitize_string(summary) if summary else None
        content = sanitize_string(content) if content else None
        
        if not title or not url or not source:
            logger.warning("Invalid article data: missing required fields")
            return None
        
        if self.article_exists(url, title):
            return None
        
        content_hash = self.get_content_hash(url, title)
        
        article = Article(
            title=title,
            url=url,
            source=source,
            date=date,
            content_hash=content_hash,
            cve_numbers=json.dumps(cve_numbers) if cve_numbers else None,
            mitre_attack_ids=json.dumps(mitre_attack_ids) if mitre_attack_ids else None,
            categories=json.dumps(categories) if categories else None,
            keywords=json.dumps(keywords) if keywords else None,
            summary=summary,
            content=content,
            cve_details=json.dumps(cve_details) if cve_details else None
        )
        
        try:
            self.session.add(article)
            self.session.commit()
            return article
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error adding article: {e}")
            return None
    
    def add_articles_batch(self, articles_data):
        """Add multiple articles in a single transaction (batch insert for performance)."""
        if not articles_data:
            return []
        
        # Generate content hashes for all articles
        content_hashes = []
        articles_to_add = []
        
        for article_data in articles_data:
            title = article_data.get('title', '')
            url = article_data.get('url', '')
            content_hash = self.get_content_hash(url, title)
            content_hashes.append(content_hash)
            articles_to_add.append((article_data, content_hash))
        
        # Bulk check which articles already exist
        existing_hashes = self.articles_exist_bulk(content_hashes)
        
        # Prepare new articles with validation
        new_articles = []
        for article_data, content_hash in articles_to_add:
            if content_hash in existing_hashes:
                continue  # Skip existing articles
            
            # Validate required fields
            title = article_data.get('title', '').strip()
            url = article_data.get('url', '').strip()
            source = article_data.get('source', '').strip()
            date = article_data.get('date')
            
            if not title or not url or not source:
                logger.warning(f"Skipping article in batch insert - missing required fields: title={bool(title)}, url={bool(url)}, source={bool(source)}")
                continue
            
            if date is None:
                logger.warning(f"Skipping article in batch insert - missing date: {title[:50]}...")
                continue
            
            article = Article(
                title=title,
                url=url,
                source=source,
                date=date,
                content_hash=content_hash,
                cve_numbers=json.dumps(article_data.get('cve_numbers')) if article_data.get('cve_numbers') else None,
                mitre_attack_ids=json.dumps(article_data.get('mitre_attack_ids')) if article_data.get('mitre_attack_ids') else None,
                categories=json.dumps(article_data.get('categories')) if article_data.get('categories') else None,
                keywords=json.dumps(article_data.get('keywords')) if article_data.get('keywords') else None,
                summary=article_data.get('summary'),
                content=article_data.get('content'),
                cve_details=json.dumps(article_data.get('cve_details')) if article_data.get('cve_details') else None
            )
            new_articles.append(article)
        
        # Batch insert
        if new_articles:
            try:
                self.session.bulk_save_objects(new_articles)
                self.session.commit()
                logger.info(f"Batch inserted {len(new_articles)} articles")
                return new_articles
            except Exception as e:
                self.session.rollback()
                logger.error(f"Error in batch insert: {e}")
                # Fallback to individual inserts
                return self._add_articles_individual(new_articles)
        
        return []
    
    def _add_articles_individual(self, articles):
        """Fallback: add articles individually if batch insert fails."""
        added = []
        for article in articles:
            try:
                self.session.add(article)
                self.session.commit()
                added.append(article)
            except Exception as e:
                self.session.rollback()
                logger.warning(f"Failed to add article {article.url}: {e}")
        return added
    
    @contextmanager
    def get_session(self):
        """Context manager for database sessions."""
        session = self.session
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            pass  # Don't close the main session
    
    def update_article_content(self, article_id, summary=None, content=None, cve_details=None):
        """Update article content and details."""
        article = self.session.query(Article).filter_by(id=article_id).first()
        if article:
            if summary is not None:
                article.summary = summary
            if content is not None:
                article.content = content
            if cve_details is not None:
                article.cve_details = json.dumps(cve_details)
            self.session.commit()
            return article
        return None
    
    def get_recent_articles(self, days=3, limit=100):
        """Get recent articles."""
        cutoff = datetime.utcnow() - timedelta(days=days)
        return self.session.query(Article).filter(
            Article.date >= cutoff
        ).order_by(Article.date.desc()).limit(limit).all()
    
    def get_yesterday_articles(self):
        """Get articles scraped yesterday (based on created_at, not publication date)."""
        # Use created_at to show articles scraped yesterday
        # This makes more sense than using publication date since RSS feeds often have old dates
        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        yesterday_start = today_start - timedelta(days=1)
        return self.session.query(Article).filter(
            Article.created_at >= yesterday_start,
            Article.created_at < today_start
        ).order_by(Article.created_at.desc()).all()
    
    def get_today_articles(self):
        """Get articles scraped today (based on created_at, not publication date)."""
        # Use created_at to show articles scraped in the last 24 hours
        # This makes more sense than using publication date since RSS feeds often have old dates
        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        return self.session.query(Article).filter(
            Article.created_at >= today_start
        ).order_by(Article.created_at.desc()).all()
    
    def get_unsent_articles(self, limit=100):
        """
        Get all articles that haven't been sent yet (regardless of date).
        This allows sending all unsent articles in daily emails.
        """
        # Get articles that have never been sent (last_sent_at is NULL)
        return self.session.query(Article).filter(
            Article.last_sent_at.is_(None)
        ).order_by(Article.date.desc()).limit(limit).all()
    
    def get_unsent_articles_today(self, limit=100):
        """
        DEPRECATED: Use get_unsent_articles() instead.
        Kept for backward compatibility.
        Get all articles that haven't been sent yet (regardless of date).
        """
        return self.get_unsent_articles(limit=limit)
    
    def mark_articles_as_sent(self, article_ids):
        """
        Mark articles as sent by updating their last_sent_at timestamp.
        
        Args:
            article_ids: List of article IDs to mark as sent
            
        Returns:
            Number of articles successfully marked
        """
        if not article_ids:
            return 0
        
        try:
            now = datetime.utcnow()
            updated = self.session.query(Article).filter(
                Article.id.in_(article_ids)
            ).update(
                {Article.last_sent_at: now},
                synchronize_session=False
            )
            self.session.commit()
            logger.info(f"Marked {updated} articles as sent")
            return updated
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error marking articles as sent: {e}")
            return 0
    
    def get_articles_by_cve(self, cve_number):
        """Get articles containing specific CVE (using parameterized query to prevent SQL injection)."""
        # Validate CVE format first
        from .utils import is_valid_cve
        if not is_valid_cve(cve_number):
            logger.warning(f"Invalid CVE format in query: {cve_number}")
            return []
        
        # Use parameterized query with proper escaping
        # SQLAlchemy's like() with bindparam prevents SQL injection
        from sqlalchemy import bindparam
        return self.session.query(Article).filter(
            Article.cve_numbers.like(bindparam('cve', f'%{cve_number}%'))
        ).params(cve=f'%{cve_number}%').all()
    
    def add_recipient(self, email, name=None, preferences=None, consent_given=True):
        """
        Add or update recipient with GDPR compliance.
        
        Args:
            email: Email address (will be validated and sanitized)
            name: Optional name
            preferences: Optional preferences dict
            consent_given: Whether user gave GDPR consent
            
        Returns:
            Recipient object or None if invalid
        """
        from .utils import sanitize_email
        from .security import GDPRCompliance
        
        # Validate and sanitize email
        email = sanitize_email(email)
        if not email:
            logger.warning(f"Invalid email address provided: {email}")
            return None
        
        # Check GDPR consent
        if not GDPRCompliance.can_store_email(email, consent_given):
            logger.warning(f"GDPR consent not given for email: {email}")
            return None
        
        # Sanitize name
        if name:
            name = sanitize_string(name, max_length=100)
        
        # Sanitize preferences
        if preferences:
            if isinstance(preferences, dict):
                preferences = json.dumps(preferences)
            else:
                preferences = None
        
        recipient = self.session.query(Recipient).filter_by(email=email).first()
        if recipient:
            if name:
                recipient.name = name
            if preferences:
                recipient.preferences = preferences
            recipient.active = True
        else:
            recipient = Recipient(
                email=email,
                name=name,
                preferences=preferences,
                active=True
            )
            self.session.add(recipient)
        
        try:
            self.session.commit()
            return recipient
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error adding recipient: {e}")
            return None
    
    def delete_recipient(self, email: str) -> bool:
        """
        Delete recipient data (GDPR right to be forgotten).
        
        Args:
            email: Email address to delete
            
        Returns:
            True if deleted, False otherwise
        """
        from .utils import sanitize_email
        
        email = sanitize_email(email)
        if not email:
            return False
        
        recipient = self.session.query(Recipient).filter_by(email=email).first()
        if recipient:
            try:
                self.session.delete(recipient)
                self.session.commit()
                logger.info(f"Deleted recipient data for GDPR compliance: {email}")
                return True
            except Exception as e:
                self.session.rollback()
                logger.error(f"Error deleting recipient: {e}")
                return False
        return False
    
    def get_recipient_data_export(self, email: str) -> dict:
        """
        Get recipient data for GDPR data export request.
        
        Args:
            email: Email address
            
        Returns:
            Dictionary with recipient data
        """
        from .utils import sanitize_email
        
        email = sanitize_email(email)
        if not email:
            return {}
        
        recipient = self.session.query(Recipient).filter_by(email=email).first()
        if recipient:
            return recipient.to_dict()
        return {}
    
    def get_active_recipients(self):
        """Get all active recipients."""
        return self.session.query(Recipient).filter_by(active=True).all()
    
    def log_email(self, article_count, recipient_count, success=True, error_message=None):
        """Log email sending."""
        log = EmailLog(
            article_count=article_count,
            recipient_count=recipient_count,
            success=success,
            error_message=error_message
        )
        self.session.add(log)
        self.session.commit()
        return log
    
    def get_statistics(self, days=30):
        """Get statistics for last N days."""
        cutoff = datetime.utcnow() - timedelta(days=days)
        return self.session.query(Statistic).filter(
            Statistic.date >= cutoff
        ).order_by(Statistic.date.desc()).all()
    
    def close(self):
        """Close database connection."""
        self.session.close()
