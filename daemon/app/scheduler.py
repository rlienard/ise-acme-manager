"""
Background scheduler for automatic certificate checks and renewals.
"""

import logging
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from .database import SessionLocal, DaemonStatus
from .config import ConfigManager
from .services.acme_renewal import ACMERenewalEngine

logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler()
renewal_engine = ACMERenewalEngine()


def scheduled_renewal():
    """Called by the scheduler to perform automatic renewal."""
    logger.info("Scheduled renewal triggered")
    try:
        renewal_engine.run(trigger="scheduled")
    except Exception as e:
        logger.error(f"Scheduled renewal failed: {e}")


def update_next_run():
    """Update the next run time in the database."""
    db = SessionLocal()
    try:
        jobs = scheduler.get_jobs()
        if jobs:
            next_run = jobs[0].next_run_time
            status = db.query(DaemonStatus).first()
            if status:
                status.next_run_at = next_run
                db.commit()
    finally:
        db.close()


def configure_scheduler():
    """Configure the scheduler based on database settings."""
    db = SessionLocal()
    try:
        enabled = ConfigManager.get(db, "scheduler_enabled", True)
        hour = ConfigManager.get(db, "scheduler_cron_hour", 2)
        minute = ConfigManager.get(db, "scheduler_cron_minute", 0)

        # Remove existing jobs
        scheduler.remove_all_jobs()

        if enabled:
            trigger = CronTrigger(hour=hour, minute=minute)
            scheduler.add_job(
                scheduled_renewal,
                trigger=trigger,
                id="acme_renewal",
                name="ACME Certificate Renewal",
                replace_existing=True,
                misfire_grace_time=3600
            )
            logger.info(f"Scheduler configured: daily at {hour:02d}:{minute:02d}")
        else:
            logger.info("Scheduler is disabled")

        update_next_run()
    finally:
        db.close()


def start_scheduler():
    """Start the background scheduler."""
    if not scheduler.running:
        scheduler.start()
        configure_scheduler()
        logger.info("Scheduler started")


def stop_scheduler():
    """Stop the background scheduler."""
    if scheduler.running:
        scheduler.shutdown()
        logger.info("Scheduler stopped")
