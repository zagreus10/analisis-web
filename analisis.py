import argparse
from funciones import busquedaCorreos, eliminarArchivosPrevios, leer_k, virus_api

if __name__ == '__main__':
    """
    Lista de funciones 
    """
    eliminarArchivosPrevios()
    parser = argparse.ArgumentParser(description="Codigo con herramientas de ciberseguridad")
    parser.add_argument("-url", dest="url", help="Ingrese una url de la web a analizar")
    parser.add_argument("-sct", metavar="ScannTarget", dest="ScnTarget", help="Nombre del archivo a analizar")
    params = parser.parse_args()

    if params.ScnTarget:
        """
        Opcion de escanera (si se selecciono) para API VirusTotal y leer key
        """
        if len(params.ScnTarget) > 0 : 
            file = params.ScnTarget
            key = leer_k()
            if key:
                info = virus_api(file, key)
                with open("report_file.txt", "w") as f:
                    f.write(info)

    if params.url:
        """
        Scrapping web y eliminar archivos previos 
        """
        if len(params.url) > 0:
            eliminarArchivosPrevios()
            busquedaCorreos(params.url)
        else:
            print("La URL es requerida")


