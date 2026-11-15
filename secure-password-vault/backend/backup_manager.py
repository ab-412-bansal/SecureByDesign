from fastapi import APIRouter, HTTPException

from schemas import BackupRequest


router = APIRouter()


@router.post("/backup-vault", status_code=501)
def backup_vault(_req: BackupRequest):
	raise HTTPException(
		status_code=501,
		detail="Vault backup is not implemented yet; no backup file was created.",
	)
