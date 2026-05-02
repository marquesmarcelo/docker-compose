from fastapi import FastAPI, HTTPException

app = FastAPI(title="Fake Data API")

# Simulando um banco de dados de infraestrutura (seu domínio de especialidade)
DB = {
    "srv-01": {"nome": "Servidor de Produção", "cpu": "12%", "memoria": "4GB/16GB", "status": "online"},
    "srv-02": {"nome": "Cluster Kubernetes Dev", "cpu": "85%", "memoria": "30GB/32GB", "status": "alerta"},
    "db-01": {"nome": "PostgreSQL Legado", "cpu": "2%", "memoria": "1GB/8GB", "status": "offline"}
}

@app.get("/")
async def health_check():
    return {"status": "healthy"}

@app.get("/items/{item_id}")
async def get_item(item_id: str):
    if item_id not in DB:
        raise HTTPException(status_code=404, detail="Item não encontrado no inventário")
    return DB[item_id]

@app.get("/items")
async def list_items():
    return DB