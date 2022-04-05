from concurrent.futures import thread
from pydantic import BaseModel

class ScanConfig(BaseModel):
    type : str
    src_ip : str
    dst_ip : str
    min_port : int
    max_port : int
    thread : int
    delay : int 

class FloodConfig(BaseModel):
    dst_ip: str
    dst_port: int
    delay: int
    thread: int

class ArpConfig(BaseModel):
    at_mac : str
    vt_mac : str
    gw_mac : str
    vt_ip : str
    gw_ip : str


class SendMail(BaseModel):
    email : str
    subject : str
    filename : str
    filepath : str