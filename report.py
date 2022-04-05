from email import encoders
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
from reportlab.platypus import Table
from reportlab.platypus import TableStyle
from reportlab.platypus import Paragraph
from reportlab.platypus import SimpleDocTemplate
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT, TA_CENTER, TA_RIGHT
import json
import datetime
from types import SimpleNamespace
import os


def CreatePDF(srcAddr, desAddr, atkType):
    data = [['Time', 'Source Address', 'Source Port',
             'Destination Address', 'Destination Port', "Attack Type"]]

    with open("../IDS2021/logs/detection.log", "r") as log:
        for line in log:
            temp = json.loads(line)
            date_time_obj = datetime.datetime.strptime(
                temp["ts"], '%Y-%m-%d %H:%M:%S.%f')
            time = str(date_time_obj.hour) + ":" + \
                str(date_time_obj.minute) + ":" + str(date_time_obj.second)

            # Ktra cac dieu kien
            if srcAddr == temp["src_ip"] and desAddr == temp["des_ip"] and atkType == temp["type"]:
                data.append([time, temp["src_ip"], temp["src_port"],
                             temp["des_ip"], temp["des_port"], temp["type"]])
            elif srcAddr == "" and desAddr == "" and atkType == temp["type"]:
                data.append([time, temp["src_ip"], temp["src_port"],
                             temp["des_ip"], temp["des_port"], temp["type"]])
            elif srcAddr == "" and desAddr == temp["des_ip"] and atkType == "":
                data.append([time, temp["src_ip"], temp["src_port"],
                             temp["des_ip"], temp["des_port"], temp["type"]])
            elif srcAddr == temp["src_ip"] and desAddr == "" and atkType == "":
                data.append([time, temp["src_ip"], temp["src_port"],
                             temp["des_ip"], temp["des_port"], temp["type"]])
            elif srcAddr == "" and desAddr == temp["des_ip"] and atkType == temp["type"]:
                data.append([time, temp["src_ip"], temp["src_port"],
                             temp["des_ip"], temp["des_port"], temp["type"]])
            elif srcAddr == temp["src_ip"] and desAddr == "" and atkType == temp["type"]:
                data.append([time, temp["src_ip"], temp["src_port"],
                             temp["des_ip"], temp["des_port"], temp["type"]])
            elif srcAddr == temp["src_ip"] and desAddr == temp["des_ip"] and atkType == "":
                data.append([time, temp["src_ip"], temp["src_port"],
                             temp["des_ip"], temp["des_port"], temp["type"]])
            elif srcAddr == "" and desAddr == "" and atkType == "":
                data.append([time, temp["src_ip"], temp["src_port"],
                             temp["des_ip"], temp["des_port"], temp["type"]])

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
    date = Paragraph(datetime.datetime.now().strftime(
        "%B %d, %Y"), stylesheet['Date_CENTER'])

    elems = []
    elems.append(header)
    elems.append(date)
    elems.append(table)

    filename = str(datetime.datetime.now().date()) + ".pdf"
    # if os.path.isfile("report/" + filename):
    #     os.remove("report/" + filename)
    #     return
    pdf = SimpleDocTemplate(
        "report/" + filename,
        pagesize=A4
    )
    pdf.build(elems)
    return filename


# def