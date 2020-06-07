#!/usr/bin/env python3

import feedparser
import re
from requests_html import HTMLSession
import html2text

def extractData(s):
    ret = {"URL": [], "IP": [], "Domain": [], "email-src": [], "subject":[], "MD5": [], "SHA1": [], "SHA256": []}
    url = re.search("\*\*(.*URL.*)\*\*\s(.*)",s.strip(),re.IGNORECASE);
    ip1 = re.search("\*\*(.*IP.*)\*\*\s(.*)",s.strip(),re.IGNORECASE);
    sen = re.search("\*\*(.*Sender.*)\*\*\s(.*)",s.strip(),re.IGNORECASE);
    smtp = re.search("\*\*(.*Smtp Host.*)\*\*\s(.*)",s.strip(),re.IGNORECASE);
    dom = re.search("\*\*(.*Dominio.*)\*\*\s(.*)",s.strip(),re.IGNORECASE);
    subj = re.search("\*\*(.*Asunto.*)\*\*\s(.*)",s.strip(),re.IGNORECASE);

    re_ip = r'[0-9]{1,3}\[?\.\]?[0-9]{1,3}\[?\.\]?[0-9]{1,3}\[?\.\]?[0-9]{1,3}'

    if url is not None:
        for i in url.group(2).strip().split("  "):
            ret["URL"].append({"comment": url.group(1), "data": i})
    if ip1 is not None:
        for i in ip1.group(2).strip().split("  "):
            ret["IP"].append({"comment": ip1.group(1), "data": i})
    if sen is not None:
        for i in sen.group(2).strip().split("  "):
            ip = re.search(re_ip, i)
            if ip is not None:
                ret["IP"].append({"comment": sen.group(1), "data": ip.group()})
            elif "@" in i:
                ret["email-src"].append({"comment": sen.group(1), "data": i})
            else:
                ret["Domain"].append({"comment": sen.group(1), "data": i})
    if smtp is not None:
        for i in smtp.group(2).strip().split("  "):
            ip = re.search(re_ip, i)
            if ip is not None:
                ret["IP"].append({"comment": smtp.group(1), "data": ip.group()})
            elif "@" in i:
                ret["email-src"].append({"comment": smtp.group(1), "data": i})
            else:
                ret["Domain"].append({"comment": smtp.group(1), "data": i})
    if dom is not None:
        for i in dom.group(2).strip().split("  "):
            ret["Domain"].append({"comment": dom.group(1), "data": i})
    if subj is not None:
        for i in subj.group(2).strip().split("  "):
            ret["subject"].append({"comment": subj.group(1), "data": i})
    return ret

alert_file = "last_alert.txt"
base_url = "https://www.csirt.gob.cl"
url = base_url+"/alertas/"
user_agent = 'Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0'
h = html2text.HTML2Text()
session = HTMLSession()

try:
    f = open(alert_file,"r")
    last = f.readline()         # Ultima alerta parseada anteriormente
    f.close()
except:
    last = None
first = ""                  # Primera alerta parseada ahora

o = session.get(url, headers = {'User-Agent': user_agent})
for c in o.html.find(".card-body"):
    for l in c.links:
        if first == "":
            first = l

        if last in l:
            f = open(alert_file,"w")
            f.write(first)
            f.close()
            exit()
        x = re.search("https?://(www.)?csirt.gob.cl/alertas/([a-z0-9-]+)", base_url+l)
        if x is not None:
            r = session.get(x.group(), headers = {'User-agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0'})
            res = h.handle(r.text).replace('\n', " ").replace("Â ","")
            t  = re.search("\*\*Indicadores de compromisos?\*\*(.*)\*\*Recomendaciones", res)
            arr = t.group(1).strip().replace(" **","\n**").split("\n")
            ret = {"URL": [], "IP": [], "Domain": [], "email-src": [], "subject": [], "MD5": [], "SHA1": [], "SHA256": [], "Completo": t.group(1).strip()}
            print("Comenzando con: " + x.group())
            for i in arr:
                output = extractData(i)
                for key in output:
                    ret[key].extend(output[key])
            print(ret)
        print("\n\n")

f = open(alert_file,"w")
f.write(first)
f.close()
