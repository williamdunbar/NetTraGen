from fastapi import FastAPI, File, UploadFile, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
import os
import json
from model import ScanConfig, FloodConfig, ArpConfig


class ScanConfig(BaseModel):
    type : str
    src_ip : str
    dst_ip : str
    min_port : int
    max_port : int
    thread : int
    delay : int 

app =FastAPI()
app.mount("/statics", StaticFiles(directory="statics", html=True), name="statics")
templates = Jinja2Templates(directory="templates")

@app.get("/")
@app.get("/index.html")
async def read_root(request: Request, response_class=HTMLResponse ):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/network", response_class=HTMLResponse)
@app.get("/network.html", response_class=HTMLResponse)
async def read_network(request: Request):
    return templates.TemplateResponse("network.html",{"request": request})

@app.get("/pentest", response_class=HTMLResponse)
@app.get("/pentest.html", response_class=HTMLResponse)
async def read_pentest(request: Request):
    return templates.TemplateResponse("pentest.html", {"request": request})

@app.post("/pentest/scan")
async def read_scan(item: ScanConfig, request: Request):
    cmd = "cd modules; sudo python3 socket_scan.py --target 192.168.133.142 --min 1 --max 2000 --delay 1 --scantype s"
    syntax = "cd modules; sudo python3 socket_scan.py --target "+ str(item.dst_ip) + " --scantype " + str(item.type) + " --min " +str(item.min_port)+ " --max " + str(item.max_port) + " --delay "+str(item.delay)
    os.system(cmd)
    response = RedirectResponse('/result/scan', status_code=303)
    # print(json_data)
    return response

@app.post("/pentest/flood")
async def read_scan(item: FloodConfig, request: Request):
    cmd = "cd modules; sudo python3 socket_flood.py --dstIp 192.168.133.142 --dstPort 7000 --delay 1000 --thread 1000"
    syntax = "cd modules; sudo python3 socket_flood.py --dstIp" + item.dst_ip+ "--dstPort"+ item.dst_port + "--delay" + item.delay + "--thread" + item.thread
    os.system(cmd)
    response = RedirectResponse('/result/flood', status_code=303)
    # print(json_data)
    return response

@app.post("/pentest/arp")
async def read_scan(item: ArpConfig, request: Request):
    cmd = "cd modules; sudo python3 arp.py -aM '00:0C:29:7F:05:7D' -vM '00:0C:29:EA:26:44' -gM '00:0C:29:1E:C1:27' -vI '20.20.20.24' -gI '20.20.20.21'"
    syntax = "cd modules; sudo python3 arp.py -aM " + item.at_mac + " -vM " + item.vt_mac + " -gM " + item.gw_mac + " -vI " + item.vt_ip + " -gI " + item.gw_ip
    print(syntax)
    # os.system(syntax)
    response = RedirectResponse('/result/arp', status_code=303)
    # print(json_data)
    # return response
    return {"message": "welcome to FastAPI!"}


@app.get("/result", response_class=HTMLResponse)
@app.get("/result.html", response_class=HTMLResponse)
async def read_pentest(request: Request):
    return templates.TemplateResponse("result_scan.html", {"request": request})

    
@app.get("/result/scan", response_class=HTMLResponse)
async def read_result_scan(request: Request ):
    result = read_json_file(file_name= 'log/scan_temp.json')
    print(result)
    # return result
    return templates.TemplateResponse("result_scan.html", {"request": request, "data": result})

@app.get("/result/flood", response_class=HTMLResponse)
async def read_result_scan(request: Request ):
    result = read_json_file(file_name= 'log/flood_temp.json')
    print(result)
    # return result
    return templates.TemplateResponse("result_flood.html", {"request": request, "data": result}) 
 
@app.get("/result/arp", response_class=HTMLResponse)
async def read_result_scan(request: Request ):
    result = read_json_file(file_name= 'log/poisoning_temp.json')
    return templates.TemplateResponse("result_poisoning.html", {"request": request, "data": result})

def read_json_file(file_name):
    with open(file_name) as opened_file:
        json_data = json.load(opened_file)
        return json_data


@app.get("/report")
@app.get("/report.html")
async def read_network(request: Request):
    return templates.TemplateResponse("report.html",{"request": request})

@app.get("/console")
@app.get("/console.html")
async def read_network(request: Request):
    return templates.TemplateResponse("console.html",{"request": request})