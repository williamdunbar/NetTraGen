from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel


class ScanConfig(BaseModel):
    type : str
    src_ip : str
    dst_ip : str
    min_port : str
    max_port : str
    thread : str
    delay : str

app =FastAPI()
app.mount("/statics", StaticFiles(directory="statics", html=True), name="statics")
templates = Jinja2Templates(directory="templates")

@app.get("/")
@app.get("/index.html")
async def read_root(request: Request, response_class=HTMLResponse ):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/pentest")
@app.get("/pentest.html")
async def read_pentest(request: Request):
    return templates.TemplateResponse("pentest.html", {"request": request})

@app.post("/pentest/scan")
async def read_scan(item: ScanConfig):
    print(item)
    return "Nhận dữ liệu thành công"

@app.get("/network")
@app.get("/network.hmtl")
async def read_network(request: Request):
    return templates.TemplateResponse("network.html",{"request": request})

@app.get("/report")
@app.get("/report.html")
async def read_network(request: Request):
    return templates.TemplateResponse("report.html",{"request": request})

@app.get("/console")
@app.get("/console.html")
async def read_network(request: Request):
    return templates.TemplateResponse("console.html",{"request": request})