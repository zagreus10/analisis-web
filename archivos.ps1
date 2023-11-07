$path = "./investigacion" 

If(!(test-path -PathType container $path)) { New-Item -ItemType Directory -Path $path }
echo "Ya casi termina...."
Move-Item -Path "./investigacionDominio.json" -Destination "./investigacion"
Move-Item -Path "./metaimagenes.json" -Destination "./investigacion"
Move-Item -Path "./metapdfs.json" -Destination "./investigacion"
Move-Item -Path "./investigacionTecnologias.json" -Destination "./investigacion" 