from email import encoders
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import json
from datetime import datetime
from types import SimpleNamespace
import os
from prexview import PrexView


# def CreatePDF(atkType):
#     link = ""
#     if(atkType == 'scan'):
#         link = "log/scan_temp.json"
#     elif(atkType == 'flood'):
#         link = "log/flood_temp.json"

#     with open(link, "r") as log:
#         for line in log:
#             temp = json.loads(line)
#             date_time_obj = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
#             print(temp)
#             # time = str(date_time_obj.hour) + ":" + \
#             #     str(date_time_obj.minute) + ":" + str(date_time_obj.second)
#             # if atkType == 'flood':
#             #     data = [['Time', 'Source Address', 'Source Port',
#             #  'Destination Address', 'Destination Port', "Attack Type"]]
#             #     data.append([date_time_obj, temp["src_ip"], temp["src_port"],
#             #                  temp["des_ip"], temp["des_port"], "syn flood"])
#             # elif atkType == 'scan':
#             #     data = [['Time', 'Destination Address', 'Scanned Port', 'Service', 'State' ,"Attack Type"]]
#             #     data.append([date_time_obj, temp["victim_ip"], temp["port"],
#             #                  temp["service"], temp["state"], "syn scan"])
#             # Ktra cac dieu kien

#     table = Table(data)

#     style = TableStyle([
#         ("BACKGROUND", (0, 0), (5, 0), colors.cadetblue),
#         ("ALIGN", (0, 0), (5, 0), "CENTER"),
#         # ("GRID", (0, 0), (-1, -1), 1, colors.gray),
#         ("TEXTCOLOR", (0, 0), (5, 0), colors.white),
#     ])

#     rowNumb = len(data)
#     for i in range(1, rowNumb):
#         if i % 2 == 0:
#             bc = colors.lightgrey
#         else:
#             bc = colors.white
#         ts = TableStyle([
#             ("BACKGROUND", (0, i), (-1, i), bc),
#         ])
#         table.setStyle(ts)

#     table.setStyle(style)

#     stylesheet = getSampleStyleSheet()
#     stylesheet.add(ParagraphStyle(name='Heading_CENTER',
#                                   parent=stylesheet['Heading1'],
#                                   alignment=TA_CENTER,
#                                   fontSize=20,
#                                   spaceBefore=0,
#                                   ))
#     stylesheet.add(ParagraphStyle(name='Date_CENTER',
#                                   parent=stylesheet['Normal'],
#                                   alignment=TA_CENTER,
#                                   fontSize=12,
#                                   #   leading=40,
#                                   spaceBefore=0,
#                                   spaceAfter=20,
#                                   ))

#     header = Paragraph("Daily Report", stylesheet['Heading_CENTER'])
#     date = Paragraph(datetime.datetime.now().strftime(
#         "%B %d, %Y"), stylesheet['Date_CENTER'])

#     elems = []
#     elems.append(header)
#     elems.append(date)
#     elems.append(table)

#     filename = str(datetime.datetime.now().date()) + ".pdf"
#     # if os.path.isfile("report/" + filename):
#     #     os.remove("report/" + filename)
#     #     return
#     pdf = SimpleDocTemplate(
#         "report/" + filename,
#         pagesize=A4
#     )
#     pdf.build(elems)
#     return filename


# # def


# CreatePDF("scan")


pxv = PrexView();

options = {'template': 'supported_languages', 'output': 'pdf'}

json = {
  'languages': [
    {'code': 'en', 'name': 'English'},
    {'code': 'es', 'name': 'Español'},
    {'code': 'fr', 'name': 'Française'}
  ]
}

file = 'test.pdf'

try:
  res = pxv.sendJSON(json, options)

  with open(file, 'wb') as f:
    f.write(res['file'])
    f.close()

  print("File created:", file)
except Exception as e:
  print(str(e))