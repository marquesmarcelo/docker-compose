from fastapi import APIRouter, Depends
from pydantic import BaseModel
from use_cases.query_use_case import QueryUseCase
from api.dependencies import get_query_use_case

router = APIRouter()

class QueryRequest(BaseModel):
    question: str

@router.post("/query")
def query(
    req: QueryRequest,
    use_case: QueryUseCase = Depends(get_query_use_case)
):
    result = use_case.execute(req.question)
    return result
