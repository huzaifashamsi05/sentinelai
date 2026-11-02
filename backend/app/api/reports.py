from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
import io

from app.api.deps import get_current_user
from app.db.database import get_db
from app.services.report_service import generate_report_pdf

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/generate")
def generate_report(db: Session = Depends(get_db), _user=Depends(get_current_user)):
    pdf_bytes = generate_report_pdf(db)
    filename = f"sentinelai_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
