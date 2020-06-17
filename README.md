# **LeakCollector**

LeakCollector es una herramienta en python3 el cual integra la conocida herramienta [**pwndb**](https://github.com/davidtavarez/pwndb) con la API de [**haveibeenpwned**](https://haveibeenpwned.com/API/Key) para la búsqueda y asociación de Data Leaks y Data Breachs

## **Uso**

Para utilizar la herramienta de debe especificar el target a buscar, puede ser un correo o un dominio.

```python3
usage: leakcollector.py [-h] [--target TARGET]

optional arguments:
  -h, --help       show this help message and exit
  --target TARGET  Target email/domain to search for leaks.

Version: 1.0 | Author: pep3,byt3c4t | Blog: https://blog.roit.cl/
```
