import os
import uuid
import shutil
from fastapi import APIRouter, UploadFile, File, Depends
from core.config import settings
from use_cases.ingest_use_case import IngestUseCase
from api.dependencies import get_ingest_use_case

router = APIRouter()

@router.post("/ingest")
async def ingest_file(
    file: UploadFile = File(...),
    use_case: IngestUseCase = Depends(get_ingest_use_case)
):
    file_id = str(uuid.uuid4())
    path = os.path.join(settings.UPLOAD_DIR, f"{file_id}.pdf")

    # Garante que o diretório de upload exista
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)

    with open(path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    result = use_case.execute(path)

    # Limpa o arquivo temporário
    if os.path.exists(path):
        os.remove(path)

    return result
