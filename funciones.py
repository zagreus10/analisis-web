import argparse
import socket 
import sys
import requests
from bs4 import BeautifulSoup
import html5lib
from shutil import move
import re
import os, time
from googlesearch import search
from PIL.ExifTags import TAGS, GPSTAGS
from PIL import Image
from glob import glob
from PyPDF2 import PdfReader
import json as j
import whois 
import builtwith
import subprocess
import hashlib #Leer hash de un archivo y enviarlo a virus total
from virus_total_apis import PublicApi #Libreria de virus total
import logging #Imprimie informacion a la consola en un archivo 

logging.basicConfig(filename='myapp.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def leer_k():

    """
    Funcion para leer el archivo que contiene la apikey
    """
    try:
        with open("apikey.txt", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        print("No existe apikey.txt. Agrega en la carpeta el archivo y coloca tu API_Key en él desde virus total.")
        return None

def virus_api(file, key):

    """
    Utiliza api virustotal para analizar si existe malware en un archivo
    """
    api = PublicApi(key)
    """
    Crear archivo que almacena los resultados
    """
    with open(file, "rb") as f:
        hash_md5 = hashlib.md5(f.read()).hexdigest()
    
    resp = api.get_file_report(hash_md5)

    info = ""

    
    if "response_code" in resp and resp["response_code"] == 200:

        """
        Revisar si el resultado ha sido recibido o haya conexion
        """
        if "results" in resp:
            msg = resp["results"].get("verbose_msg", "...")
            info += f'Verbose message: {msg}\n'

            if "positives" in resp["results"]:
                if resp["results"]["positives"] > 0:
                    info += "Archivo malicioso\n"
                else:
                    info += "Archivo seguro\n"
            """
            Contenido que destacaremos del dicciconario en un informe  
            """
            sha1 = resp["results"].get("sha1", "sin datos")
            sha256 = resp["results"].get("sha256", "sin datos")
            fecha = resp["results"].get("scan_date", "sin datos")
            total = resp["results"].get("total", "sin datos")
            permalink = resp["results"].get("permalink", "sin datos")

            info += f'SHA1: {sha1}\n'
            info += f'SHA256: {sha256}\n'
            info += f'Fecha escaneo: {fecha}\n'
            info += f'Motores de escaneo usados: {total}\n'
            info += f'Enlace al informe completo: {permalink}\n'

        else:
            info += "Sin resultados.\n"
    else:
        info += "No fue posible conectar.\n"
    
    return info

def eliminarArchivosPrevios():
    """ 
    Se usa para eliminar las imagenes y pdf pasados
    """
    carpetas_a_borrar = ["img", "pdf", "investigacion"]
    for carpeta in carpetas_a_borrar:
        try:
            for archivo in os.listdir(carpeta):
                ruta_archivo = os.path.join(carpeta, archivo)
                os.remove(ruta_archivo)
        except FileNotFoundError:
            pass

def invDominio(url):
    """
    Investiga los datos que se pueden obtener por el dominio de la pagina web
    """

    descargarPdfs(url)
    inv = open("investigacionDominio.json", "w", encoding="utf-8")

    try:
        """
        Hace uso del modulo whois 
        """
        info = whois.whois(url)
        

        """
        Se guardan los datos y se crea un json, despues lo guarda en un archivo en formato json    
        """

        dominio = str(info.domain_name) if hasattr(info, "domain_name") else "Desconocido"
        fechaCreacion = str(info.creation_date) if hasattr(info, "creation_date") else "Desconocido"
        fechaActualizacion = str(info.updated_date) if hasattr(info, "updated_date") else "Desconocido"
        fechaExpiracion = str(info.expiration_date) if hasattr(info, "expiration_date") else "Desconocido"
        servidores = info.name_servers if hasattr(info, "name_servers") else "Desconocido"
        nombreRegistro = info.registrant_name if hasattr(info, "registrant_name") else "Desconocido"
        ciudadRegistro = info.registrant_city if hasattr(info, "registrant_city") else "Desconocido"
        estadoRegistro = info.registrant_state if hasattr(info, "registrant_state") else "Desconocido"
        paisRegistro = info.registrant_country if hasattr(info, "registrant_country") else "Desconocido"

        arr = []

        json = { 
            "dominio": dominio, 
            "fechaCreacion": fechaCreacion, 
            "fechaActualizacion": fechaActualizacion, 
            "fechaExpiracion": fechaExpiracion, 
            "servidores": servidores, 
            "nombreRegistro" : nombreRegistro, 
            "ciudadRegistro": ciudadRegistro, 
            "estadoRegistro": estadoRegistro, 
            "paisRegistro": paisRegistro 
        }
        arr.append(json)
        j.dump(arr, inv, indent=4)
        inv.close() 
    except:
        pass

def invTec(url):
    """
    Obtiene datos con builtwhit de las tecnologias que usa la web
    """

    inv = open("investigacionTecnologias.json", "w", encoding="utf-8")

    descargarImagenes(url)
    try:    
        info = builtwith.parse(url)
        arr = []
        """
        Se crea un json para guardar la informacion, despues lo guarda en un archivo en formato json
        """
        json = { 
            "ServidorWeb" : info["web-servers"] if "web-servers" in info else "Desconocido",
            "Widgets" : info["widgets"] if "widgets" in info else "Desconocido",
            "JavaScriptFrameworks" : info["javascript-frameworks"] if "javascript-frameworks" in info else "Desconocido",
            "GalleriaFotos" : info["photo-galleries"] if "photo-galleries" in info else "Desconocido",
            "WebFrameworks" : info["web-frameworks"] if "web-frameworks" in info else "Desconocido",
            "CMS" : info["cms"] if "cms" in info else "Desconocido",
            "LenguajesDeProgramacion": info["programming-languages"] if "programming-languages" in info else "Desconocido",
            "Blogs": info["blogs"] if "blogs" in info else "Desconocido",
            "AutomatizacionDeMarketing" : info["marketing-automation"] if "marketing-automation" in info else "Desconocido"
        }   

        arr.append(json)
        j.dump(arr, inv, indent=4)
        inv.close()

    except:
        pass

    
def busquedaCorreos(url):
    """
    Extrae todo los correos encontrados en la web
    """
    
    correos = open("correos.txt", "w")
    try:
        response = requests.get(url)
        if response.status_code != 200:
            pass

        regExMail = r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+"
        new_emails = set(re.findall(regExMail, response.text, re.I))
        """
        Crea un archivo .txt y almacena los correos encontrados
        """
        for i in new_emails:
            correos.write(i + "\n")
        
        correos.close()
        
    except:
        pass
    
    invDominio(url)

def descargarImagenes(url):
    """
    Descarga las imagenes de la pagina web
    """

    try:
        html = requests.get(url)
        soup = BeautifulSoup(html.text, 'html5lib')
        imgHtmlList = soup.find_all("img")

        """
        Se crea una carpeta llamada /img , donde se almacenan las imagenes 
        """

        for i in imgHtmlList:
            try:
                imgUrl= i['src'] #Esto es lo que extrae el url de las etiquetas <img>
                if imgUrl[0] == "/":
                    imgUrl = url + imgUrl
                
                img = requests.get(imgUrl) #petición al url de la imagen
                name = imgUrl.split("/")[-1] #este nombre esta simplemente para no nombrar yo mismo el archivo
                cur_path = os.path.abspath(os.curdir)
                if not os.path.exists(os.path.join(cur_path, 'img/')):
                    os.makedirs(os.path.join(cur_path, 'img/'))
                
                open(name,'wb').write(img.content) #abrir/crear un archivo .png con el contenido de la imagen a descargar
                name = "\\" + name
                move(cur_path + name, cur_path + "\\img")
                
            except:
                pass
        
    except:
        print("Error al intentar descargar las imagenes")
        pass
    
    analizarImagenes()

def descargarPdfs(url):
    """
    Descarga los pdfs que se encuentren en la web
    """
    try:
        page = requests.get(url)    
        data = page.text
        soup = BeautifulSoup(data, features="html5lib") 
        refs = []
        for link in soup.find_all('a'):            
            refs.append(link.get('href'))

        """
        Crea una carpeta llamada /pdf , donde se almacenan los pdf encontrados
        """

        for i in refs:
            try:
                if i[-4:] == ".pdf":
                    # Peticion al archivo
                    file = requests.get(i) 
                    # Obtiene el ultimo / para nomrbrar el archivo
                    ind = i.rfind("/")
                    name = i[ind+1:] #este nombre esta simplemente para no nombrar yo mismo el archivo
                    cur_path = os.path.abspath(os.curdir)
                    if not os.path.exists(os.path.join(cur_path, 'pdf/')):
                        os.makedirs(os.path.join(cur_path, 'pdf/'))
                    
                    with open(name,'wb') as f:
                        f.write(file.content) #abrir/crear un archivo .pdf con el contenido de la imagen a descargar
                    name = "\\" + name
                    move(cur_path + name, cur_path + "\\pdf")

            except:
                pass

    except:
        print("Error al intentar descargar los archivos")
        pass
    
    analizarPdfs(url)

def analizarImagenes():
    """
    Obtiene los metadatos de las imagenes
    """
    raiz = os.path.abspath(os.curdir)
    def decode_gps_info(exif):
        gpsinfo = {}
        if 'GPSInfo' in exif:
            #Parse geo references.
            Nsec = exif['GPSInfo'][2][2] 
            Nmin = exif['GPSInfo'][2][1]
            Ndeg = exif['GPSInfo'][2][0]
            Wsec = exif['GPSInfo'][4][2]
            Wmin = exif['GPSInfo'][4][1]
            Wdeg = exif['GPSInfo'][4][0]
            if exif['GPSInfo'][1] == 'N':
                Nmult = 1
            else:
                Nmult = -1
            if exif['GPSInfo'][1] == 'E':
                Wmult = 1
            else:
                Wmult = -1
            Lat = Nmult * (Ndeg + (Nmin + Nsec/60.0)/60.0)
            Lng = Wmult * (Wdeg + (Wmin + Wsec/60.0)/60.0)
            exif['GPSInfo'] = {"Lat" : Lat, "Lng" : Lng}

    def get_exif_metadata(image_path):
        ret = {}
        try:
            image = Image.open(image_path)
            if hasattr(image, '_getexif'):
                exifinfo = image._getexif()
                if exifinfo is not None:
                    for tag, value in exifinfo.items():
                        decoded = TAGS.get(tag, tag)
                        ret[decoded] = value
            decode_gps_info(ret)
            return ret
        except:
            pass
    
    meta = []
    def printMeta():
        path = os.path.abspath(os.curdir)+"\\img\\"
        os.chdir(os.path.abspath(os.curdir)+"\\img")
        for root, dirs, files in os.walk(".", topdown=False):
            for name in files:
                if name[-4:] == ".png":
                    exifData = {}
                    try:
                        exif = get_exif_metadata(path + name)
                        json = {"nombre": name}
                        if type(exif) is not type(None):    
                            for metadata in exif:
                                var = {metadata: str(exif[metadata])}
                                json.update(var)                                
                                meta.append(json)
                    except:
                        import sys, traceback
                        traceback.print_exc(file=sys.stdout)
    printMeta()
    os.chdir(raiz)

    # Se guardan los metadatos de las imagenes en un archivo en formato json
    analisis = open("metaimagenes.json", "w", encoding="utf-8")
    j.dump(meta, analisis, indent=4)
    analisis.close()

    investigacion()
        
def analizarPdfs(url):
    """
    Obtiene los metadatos de los pdfs
    """
    path = os.path.abspath(os.curdir)+"\\pdf\\"
    pdfs = os.listdir(path)
    arr = []
    
    for pdf in pdfs:
        pdfObj = PdfReader(path + pdf)
        paginas = len(pdfObj.pages) if hasattr(pdfObj, "pages") else "Desconocido"
        titulo = pdfObj.metadata.title if hasattr(pdfObj.metadata, "title") else "Desconocido"
        autor = pdfObj.metadata.author if hasattr(pdfObj.metadata, "author") else "Desconocido"
        json = { "nombre": pdf, "titulo": titulo, "autor": autor, "np": str(paginas) }
        arr.append(str(json))

    """
    Guarda los metadatos en un archivo en formato json
    """

    analisis = open("metapdfs.json", "w", encoding="utf-8")
    j.dump(arr, analisis, indent=4)
    analisis.close()
    invTec(url)

def investigacion():
    time.sleep(10)
    # Ruta al script de PowerShell que deseas ejecutar
    script_path = os.path.abspath(os.curdir) + "\\archivos.ps1"

    # Ejecutar el script de PowerShell
    try:
        subprocess.run(["powershell", "-File", script_path], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar el script de PowerShell: {e}")