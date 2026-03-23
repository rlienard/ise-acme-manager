"""
Renewal history API endpoints.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from ..database import get_db, RenewalHistory
from ..models import RenewalHistoryResponse, RenewalHistoryList

router = APIRouter(prefix="/api/v1/history", tags=["History"])


@router.get("", response_model=RenewalHistoryList)
def get_renewal_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: str = Query(None),
    trigger: str = Query(None),
    db: Session = Depends(get_db)
):
    """Get paginated renewal history."""
    query = db.query(RenewalHistory)

    if status:
        query = query.filter(RenewalHistory.status == status)
    if trigger:
        query = query.filter(RenewalHistory.trigger == trigger)

    total = query.count()
    items = query.order_by(desc(RenewalHistory.started_at)) \
                 .offset((page - 1) * page_size) \
                 .limit(page_size) \
                 .all()

    return RenewalHistoryList(
        total=total,
        page=page,
        page_size=page_size,
        items=[RenewalHistoryResponse.model_validate(i) for i in items]
    )


@router.get("/{run_id}", response_model=RenewalHistoryResponse)
def get_renewal_detail(run_id: str, db: Session = Depends(get_db)):
    """Get detailed information about a specific renewal run."""
    record = db.query(RenewalHistory).filter(
        RenewalHistory.run_id == run_id
    ).first()

    if not record:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Run not found")

    return RenewalHistoryResponse.model_validate(record)


@router.get("/{run_id}/logs")
def get_renewal_logs(run_id: str, db: Session = Depends(get_db)):
    """Get logs for a specific renewal run."""
    record = db.query(RenewalHistory).filter(
        RenewalHistory.run_id == run_id
    ).first()

    if not record:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Run not found")

    return {"run_id": run_id, "logs": record.log_output or "No logs available"}
