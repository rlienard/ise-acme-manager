"""
Status API endpoints.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db, DaemonStatus, ISENode
from ..models import DaemonStatusResponse, ISENodeResponse
from ..config import ConfigManager

router = APIRouter(prefix="/api/v1/status", tags=["Status"])


@router.get("", response_model=DaemonStatusResponse)
def get_daemon_status(db: Session = Depends(get_db)):
    """Get current daemon status including all node statuses."""
    status = db.query(DaemonStatus).first()
    nodes = db.query(ISENode).all()

    scheduler_enabled = ConfigManager.get(db, "scheduler_enabled", True)

    return DaemonStatusResponse(
        state=status.state.value if status else "unknown",
        current_action=status.current_action if status else None,
        last_run_at=status.last_run_at if status else None,
        last_run_status=status.last_run_status if status else None,
        next_run_at=status.next_run_at if status else None,
        uptime_since=status.uptime_since if status else None,
        total_renewals=status.total_renewals if status else 0,
        successful_renewals=status.successful_renewals if status else 0,
        failed_renewals=status.failed_renewals if status else 0,
        last_error=status.last_error if status else None,
        version=status.version if status else "2.0.0",
        nodes=[ISENodeResponse.model_validate(n) for n in nodes],
        scheduler_enabled=scheduler_enabled
    )
