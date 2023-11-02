import argparse
from funciones import busquedaCorreos, eliminarArchivosPrevios

if __name__ == '__main__': 
    parser = argparse.ArgumentParser()

    parser.add_argument("-url", dest="url", help="Ingrese una url de la web a analizar",required=True)

    params = parser.parse_args()

    if len(params.url) > 0:
        """ 
        En caso de que se tengan archivos previos se elimina lo pasado y empieza a ejecutar el codigo
        """
        eliminarArchivosPrevios()
        busquedaCorreos(params.url)
        
    else:
        ("La url es requerida")