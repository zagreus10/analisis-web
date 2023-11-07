import argparse
from funciones import busquedaCorreos, eliminarArchivosPrevios, leer_k, virus_api

if __name__ == '__main__':
    #Argumento por defecto
    eliminarArchivosPrevios()
    parser = argparse.ArgumentParser(description="Codigo con herramientas de ciberseguridad")
    parser.add_argument("-url", dest="url", help="Ingrese una url de la web a analizar")
    parser.add_argument("-sct", metavar="ScannTarget", dest="ScnTarget", help="Nombre del archivo a analizar")
    params = parser.parse_args()

    if params.ScnTarget:
        file = params.ScnTarget
        key = leer_k()
        if key:
            info = virus_api(file, key)
            with open("report_file.txt", "w") as f:
                f.write(info)

    if params.url:
            """ 
            En caso de que se tengan archivos previos se elimina lo pasado y empieza a ejecutar el codigo
            """
        if len(params.url) > 0:
            busquedaCorreos(params.url)
        else:
            print("La URL es requerida")
            
