from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.models import Discrepancia

DISCREPANCIA_RETENTION_DAYS = 14


def eliminar_discrepancias_vencidas(db: Session) -> int:
    limite = datetime.now() - timedelta(days=DISCREPANCIA_RETENTION_DAYS)
    eliminadas = (
        db.query(Discrepancia)
        .filter(Discrepancia.fecha < limite)
        .delete(synchronize_session=False)
    )
    db.commit()
    return int(eliminadas or 0)
