from email import encoders
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from re import I
import smtplib
from reportlab.platypus import Table
from reportlab.platypus import TableStyle
from reportlab.platypus import Paragraph
from reportlab.platypus import SimpleDocTemplate
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT, TA_CENTER, TA_RIGHT
import json
from datetime import datetime
from types import SimpleNamespace
import os



def CreatePDF(atkType):
    link = ""
    index = 1
    if(atkType == 'scan'):
        link = "../log/scan_temp.json"
        data = [['Id','Time', 'Source Address', 'Source Port','Destination Address', 'Destination Port', "Attack Type"]]
    elif(atkType == 'flood'):
        link = "../log/flood_temp.json"
        data = [['Id','Time', 'Destination Address', 'Scanned Port', 'Service', 'State' ,"Attack Type"]]
    json_data = read_json_file(link)
    for line in json_data:
      print(line)
      date_time_obj = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
      # print(temp)
      # time = str(date_time_obj.hour) + ":" + str(date_time_obj.minute) + ":" + str(date_time_obj.second)
      if atkType == 'flood':
        
        data.append([index,date_time_obj, line["src_ip"], line["src_port"],line["dst_ip"], line["dst_port"], "syn flood"])
      elif atkType == 'scan':
        
        data.append([index,date_time_obj, line["victim_ip"], line["port"],line["service"], line["state"], "syn scan"])
            # Ktra cac dieu kien
      index += 1
     
    table = Table(data)

    style = TableStyle([
        ("BACKGROUND", (0, 0), (5, 0), colors.cadetblue),
        ("ALIGN", (0, 0), (5, 0), "CENTER"),
        # ("GRID", (0, 0), (-1, -1), 1, colors.gray),
        ("TEXTCOLOR", (0, 0), (5, 0), colors.white),
    ])

    rowNumb = len(data)
    for i in range(1, rowNumb):
        if i % 2 == 0:
            bc = colors.lightgrey
        else:
            bc = colors.white
        ts = TableStyle([
            ("BACKGROUND", (0, i), (-1, i), bc),
        ])
        table.setStyle(ts)

    table.setStyle(style)

    stylesheet = getSampleStyleSheet()
    stylesheet.add(ParagraphStyle(name='Heading_CENTER',
                                  parent=stylesheet['Heading1'],
                                  alignment=TA_CENTER,
                                  fontSize=20,
                                  spaceBefore=0,
                                  ))
    stylesheet.add(ParagraphStyle(name='Date_CENTER',
                                  parent=stylesheet['Normal'],
                                  alignment=TA_CENTER,
                                  fontSize=12,
                                  #   leading=40,
                                  spaceBefore=0,
                                  spaceAfter=20,
                                  ))

    header = Paragraph("Daily Report", stylesheet['Heading_CENTER'])
    date = Paragraph(datetime.now().strftime(
        "%B %d, %Y"), stylesheet['Date_CENTER'])

    elems = []
    elems.append(header)
    elems.append(date)
    elems.append(table)

    filename = atkType +"_"+ str(datetime.now().date()) + ".pdf"
    # if os.path.isfile("report/" + filename):
    #     os.remove("report/" + filename)
    #     return
    pdf = SimpleDocTemplate(
        "../statics/docs/" + filename,
        pagesize=A4
    )
    pdf.build(elems)
    return filename


# CreatePDF("scan")

def read_json_file(file_name):
    with open(file_name) as opened_file:
        json_data = json.load(opened_file)
        return json_data

