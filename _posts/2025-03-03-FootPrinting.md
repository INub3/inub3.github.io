---
title: FootPrinting
author: iv4sh
date: 2025-03-03 16:00:00 +0800
categories: [Teoría, Enumeración]
tags: [FootPrinting, Concepto]
render_with_liquid: false
description: Teoría sobre la enumeración de servicios basados en la infraestructura, host y protocolos de acceso remoto.
---


## **Infraestructure Based**  


> La enumeración basada en la infraestructura se basa en la composición física tanto externa como interna de la red del objetivo. Abarca la información del dominio, recursos en la nube y el personal de la empresa, toda esta es información nos puede ayudar a conocer mas acerca de nuestro objetivo y en muchos casos este será nuestro punto de inicio. 

### Información del Dominio

La información del dominio es una fundamental para conocer la presencia del objetivo en internet. Por lo tanto la recopilación de información nos ayudara a comprender la funcionalidad de la empresa, sus tecnologías y la infraestructura que hacen que esta pueda brindar sus servicios.

#### Presencia en Línea

Esencial para ampliar nuestro rango de ataque, para esto podemos basarnos en los siguientes puntos:

1. **Certificado SSL**
	Debemos examinar el permiso SSL del sitio Principal puesto que este suele incluir mas de un subdominio que en el mejor de los casos pueden seguir activos.

2. **crt.sh**
	Es un fuente de la cual podemos obtener subdominios mediante los registros del certificado de transparencia, funciona mediante la verificación de certificados digitales emitidos por una autoridad de certificaciones en registros de pentesting.
	Esta web nos permite reportar los resultados en formato JSON cómodamente desde consola:

``` bash
curl -s https://crt.sh/\?q\=<URL>\&output\=json | jq .
#Podemos filtrar los resultados por subdominios
curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u
```

3. **Servidores Alojados**
	Una vez identificados una serie de hosts podemos generar un lista de direcciones IP para ejecutarles en *Shodan*, aplicativo que se puede utilizar para encontrar dispositivos y sistemas conectados permanentemente a internet.

``` bash
# Genera la lista de ip's en funcion de los subdominios
$ for i in $(cat subdomainlist);do host $i | grep "has address" | grep <URL> | cut -d" " -f4 >> ip-addresses.txt;done
# Ejecuta shodan en cada una de las IP para buscar conincidencias
$ for i in $(cat ip-addresses.txt);do shodan host $i;done
```

4. **Certificados DNS**
	Podemos obtener todos los registros disponibles del dominio mediante la herramienta `dig`.

``` bash
dig any <URL>
```

### Recursos en la Nube

Las empresas suelean alojar respaldos en la nube, como AWS (Amazon), GCP (Google), Azure (Microsoft), a pesar de tener una protección centralizada si esta esta mal configurada la hace vulnerable. Por ejemplo: *S3 buckets* (AWS), *blobs* (Azure), *cloud storage* (GCP) a los que se puede acceder sin autentificación si se configuran de manera incorrecta.

1. **Búsqueda por Google Dorks**
	Podemos buscar respaldos en la nube de una empresa mediante búsquedas de Google Dorks, utilizando las etiquetas *inurl:* e *intext* bajo estas búsquedas podremos encontrar documentos de texto, presentaciones, códigos, código fuente, entre otros:
``` bash
# Para busquedas de AWS en Google
intext:<Nombre de la empresa> inurl:amazonaws.com
# Para busquedas de Azure
intext:<Nombre de la empresa> inurl:blob.core.windows.net
```

2. **Domain.glass**
	Una pagina web que ofrece el servicio de busqueda y consulta sobre dominios de internet. En esta podemos ingresar el dominio del respaldo en la nube y recibir información extra como su nivel de seguridad, el estatus de la pagina y mucha información relevante.

3. **GrayHatWarfare**
	Este es otro proveedor parecido al anterior, este además nos permite descubrir almacenamientos en la nube de AWS, Azure y GCP. Según la mala administración de la empresa podemos encontrar archivos de mucho riesgo como claves privadas SSH.

---

---
  
## **Host Based**  
  
  
> La enumeración basada en Host consiste en la investigación de los servicios dados por un sistema especifico en una red. Aquí entra en juego la enumeración de los puertos que brindan alguno de los siguientes servicios: FTP, SMB, NFS, DNS, SMTP, IMAP / POP3, SNMP, MySQL, MSSQL, Oracle TNS, IPMI.


### File Transfer Protocol (FTP)

El protocolo se ejecuta en la capa de aplicación mediante TCP, funciona con el puerto 21 de TCP por defecto defecto usando el puerto 20 para establecer una comunicación de transferencia de datos.
- **Activa:** La variante activa de FTP ocurre cuando se establece la conexión exclusivamente por el puerto TCP 21, sin embargo el protocolo no puede responder debido a restricciones con el firewall.
- **Pasiva:** Para este caso el servicio anuncia un puerto para establecer la conexión de este modo el firewall no lo bloquea.

Para acceder a este servicio normalmente necesitaremos de credenciales, sin embargo hay un modo de configuración que nos permite acceder como el usuario *Anonymous* el cual suele tener permisos muy limitados debido al riego de seguridad que implica.
Para podernos mover bien por los directorios compartidos por FTP es importante conocer los [códigos de estado](https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes) y [comandos](https://web.archive.org/web/20230326204635/https://www.smartfile.com/blog/the-ultimate-ftp-commands-list/).

Podemos acceder al servicio por los siguientes medios:
``` bash
# Interacción común
ftp <IP-servidorFTP>

# Mediante netcat
nc -nv <IP-servidorFTP> 21

# Por telnet
telnet <IP-servidorFTP> 21

# Si el servidor tiene cifrado TLS/SSL:
openssl s_client -connect <IP-servidorFTP>:21 -starttls ftp
```

#### Puntos Importantes

**Archivos de Configuración:**
Al intentar vulnerar un servicio puede ser importante conocer el archivo de configuración por defecto del servicio, Por ejemplo: El Gestor del servicio **vsFTPd** tiene su archivo de configuración en la ruta `/etc/vsftpd.config` y la ruta de los usuarios no permitidos en el archivo `/etc/ftpusers`.

**Descarga y subida de archivos:**
Si somos un usuario con los permisos necesarios podremos tanto descargar como subir archivos entre el servicio FTP y nuestra maquina de atacante. Para esto hacemos uso de los siguientes comandos:
`get <ruta del archivo>`: Este comando nos permite la descarga de un archivo el cual conozcamos su ruta.
`wget -m --no-passive ftp://anonymous:anonymous@<IP>`: Para descargar todo lo que el servicio nos ofrece.
`put <ruta del archivo>`: Subir un archivo al servidor FTP.


### Server Message Block (SMB)

Es un protocolo de cliente servidor que regula el acceso a archivos y directorios completos así como otros recursos de red como impresoras, enrutadores o interfaces de red. Principalmente funcional para Windows, pero el servicio *Samba* permite el uso de SMB en distribuciones basadas en Unix.

#### Samba

Samba implementa el protocolo de red CIFS (Common Internet File System) protocolo de SMB creado por Microsoft que permite la comunicación efectiva con dispositivos antiguos. Cuando Samba se comunica a través del servicio NetBIOS la conexión se producen a través de los puertos TCP *137*, *138* y *139*. Por otro lado CIFS opera exclusivamente en el puerto TCP *445*.
Existe versiones mas actuales como SMB 2 y SMB 3, SMB 1 (CIFS) se considera obsoleto pero usable en entornos específicos.

**Archivos de Configuración:**
El archivo de configuración para el servicio Samba se puede encontrar en la siguiente ruta: `/etc/samba/smb.config`. 

**Configuraciones Peligrosas:**
Existen varias configuraciones que hacen a este servicio vulnerable, algunas de estas son las siguientes:

| Configuración                | Descripción                                                            |
| ---------------------------- | ---------------------------------------------------------------------- |
| guest ok = yes               | Permite el acceso como usuario anonimo                                 |
| browseable = yes             | Permite listar los contenidos de los directorios por cualquier usuario |
| read only = no               | Permite la creación y modificación de archivos                         |
| writable = yes               | Da permisos de escritura a los usuarios                                |
| create/directory mask = 0777 | Permisos asignados a archivos y directorios recién creados             |

#### Establecer conexión con el servicio SMB

La primera manera nos permite un ingreso **interactivo** hacia el servidor SMB, desde aquí podemos hacer uso de comandos para navegar entre directorios o para descargar y cargar ficheros.
Podemos usar el comando `help` para ver todos los *comando disponibles*. También podemos anteponer `!` para ejecutar un comando en nuestra maquina sin salir del servicio.
``` bash
# Acceso con nombre de usurio y clave predeterminados
smbclient //<IP>/<Recuros compartido> -U usuario%contraseña

# Entrar al servicio con sesion nula - usuario anonymous
smbclient -N -L //<IP>

# Iniciar session desde una direcorio compartido
smbclient //<IP>/<Recuros compartido>
```

Otra manera de interactuar con el servicio es a través de **RPCclient** usada para realizar acciones MS-RPC (Remote Procedure Call).
``` bash
# Inicio de session Nulo - Usuario anonymous
rpcclient -U "" <IP>
```
**RPCclient** nos ofrece una variedad de solicitudes que podemos ejecutar en el servicio SMB para obtener información. Estas son algunas:

| Consulta          | Descripción                                        |
| ----------------- | -------------------------------------------------- |
| srvinfo           | Información del servicio                           |
| enumdomains       | Enumera todos los dominios implementados en la red |
| querydominfo      | Información de dominio, servicio y usuario         |
| netshareenumall   | Enumera todas las acciones disponibles             |
| enumdomusers      | Enumera los usuarios del dominio                   |
| queryuser < RID > | Información sobre un usuario especifico            |

Para aplicar fuerza bruta de los RID de los usuarios:
``` bash
for i in $(seq 500 1100);do rpcclient -N -U "" <IP> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
```

#### Otras Herramientas

La información que obtuvimos de RPCclient puede ser obtenida de otras herramientas como [SMBMap](https://github.com/ShawnDEvans/smbmap) y [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec), muy utilizadas para la enumeración de servicios SMB. 
``` bash
# Interacción con SMBmap
smbmap -H <IP>

# Interacción con CrackMapExec
crackmapexec smb <IP> --share -u '' -p ''

# Interacción con NetExec
nxc smb <IP> --share -u '' -p ''
```

En lugar de CrackMapExec podemos usar [NetExec](https://github.com/Pennyw0rth/NetExec) una herramienta basada en CrackMapExec pero mas actual y funcional. Se usa de la misma manera y con los mismos comandos.


### Network File System (NFS)

Tiene el mismo propósito que SMB, el cual es acceder a sistemas y archivos a través de la red como si fueran locales. en su versión mas actual *NFSv4* el usuario debe autenticarse, esta es una versión que incluye **Kerberos** y funciona a través del Firewall e internet haciéndola mas segura que sus predecesoras.

#### Autentificación

El tipo de autentificacion mas comun es en este servicio es atraves del UID/GID de los usuarios en el sistema UNIX. Dado que alguien puede replicar los permisos de los usuarios solo se debe usar en redes de confianza con configuraciones cautelosas.

**Ruta de configuración:**
La ruta de configuración del servicio NFS es `/etc/exports`, un archivo simple donde solo se especifican las rutas compartidas con una configuraciones bastante básicas.

#### Enumeración del servicio

El servicio funciona sobre los puertos *TCP 111, 2049*, con NMAP podemos obtener información mediante varios de los scripts que ofrece los mismos que abusan del host a través de RPC.

Podemos montar el servicio en nuestra maquina en un directorio vacío el cual podremos navegar libremente.
``` bash
# Mostrar opciones disponibles
showmount -e <IP>

# Montaje del recurso compartido NFS
mkdir ShareFile
sudo mount -t nfs <IP>:/ ./ShareFile/ -o nolock
cd ShareFile/

# Desmontar
cd ..
sudo umount ./ShareFile
```


### Domain Name System (DNS)

Mediante los nombres de Dominio podemos acceder a un servidor web en el que el administrados haya usado una o mas direcciones IP especificas. Por lo tanto el **DNS** es un sistema para resolver los nombres de los ordenadores en direcciones IP.

El DNS puede no esta cifrado sin embargo existe protocolos como *DNS over TLS* o *DNS over HTTPs* que lo filtran además del protocolo de red *DNSCrypt*. La comunicación con este servicio ocurre a través del puerto **TCP 53**.
  
#### Enumeración DNS

Podemos encontrar los archivos de configuración DNS en las siguientes rutas:
- `/etc/bind/named.config.local`
- `/etc/bind/named.config.options`
- `/etc/bind/named.config.log`

#### Códigos de Registro DNS

La enumeración del servicio DNS se basa en el envió de consultas hacia el dominio, existen una serie de registros que nos indican el tipo de información que estos proveen, algunos de estos son:

| Registro DNS | Descripción                                                         |
| ------------ | ------------------------------------------------------------------- |
| A            | Devuelve una dirección IPv4 del dominio solicitado                  |
| MX           | Servidores de correo                                                |
| NS           | Devuelve los nombres DNS del dominio                                |
| TXT          | Puede contener información diversa                                  |
| SOA          | Información de la zona DNS y la dirección del correo administrativo |


#### Solicitudes DNS

1. El Registro **SOA** se encuentra en el archivo de zona de un dominio y especifica al responsable del funcionamiento del dominio y como se administra la información DNS.
``` bash
dig soa <Dominios/Subdominio>
```

1. La consulta **NS** nos muestra que otros nombres de servidores conoce nuestro servidor DNS objetivo.
``` bash
dig ns <Nombre del dominio> @<IP>
```

3. Es posible consultar la **versión** del servidor DNS mediante una consulta de CHAOS y tipo TXT (esta entrada debe existir en el servidor).
``` bash
dig CH TXT version.bind <IP>
```

4. La opción **ANY** se usa para ver todos los registros disponibles que el servidor este dispuesto a revelar (No se mostraran TODAS las entradas de las zonas).
``` bash
dig any <Nombre del dominio> @<IP>
```

5. La transferencia de zona **AXFR** (Asynchronous Full Transfer Zone)se refiere a la transferencia de zona a otro servidor DNS. 
``` bash
dig axfr <Nombre del dominio> @<IP>
# Transferencia de zona interna
dig axfr internal.<Nombre del dominio> @<IP>
```
  
Los registro de tipo **A** se pueden descubrir mediante un ataque de fuerza bruta con la herramienta *dnsenum*.

``` bash
dnsenum --dnsserver <IP> --enum -p 0 -s 0 -o <Archivo-destino> -f Wordlist.txt <dominio.tld> 
```  


### Simple Mail Transfer Protocol (SMTP)

Es un Protocolo para enviar correos electrónicos en una red IP, suele combinarse con el servicio IMAP o POP3 que pueden buscar y enviar correos electrónicos. El servicio SMTP establece la conexión mediante el puerto *TCP 25*, o en versiones mas recientes por el puerto *TCP 587* para usuarios autenticados y correos cifrados mediante **STARTTLS**.

**Ruta del archivo de configuración:** `/etc/postfix/main.cf`

#### Interacción con el servicio

Podemos conectarnos al servicio por **TelNet** especificando la dirección IP y el puerto correspondiente al servicio.
``` bash
telnet <IP> 25
```
Existen varios comandos que podemos usar dentro del servicio, algunos son los siguientes:

| Comando    | Descripción                                                                      |
| ---------- | -------------------------------------------------------------------------------- |
| AUTH PLAIN | Autentica al cliente                                                             |
| HELO       | El cliente inicia sesión con el nombre de la computadora                         |
| MAIL FROM  | El cliente nombra al remitente                                                   |
| RCPT TO    | El cliente nombra al destinatario                                                |
| DATA       | El cliente inicia la transmisión del correo                                      |
| RSET       | Para cancelar la transmisión                                                     |
| VRFY       | El cliente comprueba la existencia de un buzón para la transferencia de mensajes |
| QUIT       | Finaliza la sesión                                                               |

#### Enumeración del servicio

Podemos usar los comandos **VRFY**, **EXPN** y **RCPT TO** para enumerar usuarios registrados en el servidor de correo de manera manual.

También podemos usar la herramienta SMTP-user-enum de [Pentest Monkey](https://pentestmonkey.net/tools/user-enumeration/smtp-user-enum).
  
``` bash
smtp-user-enum -M VRFY -U <wordlist> -t <IP>
```

**NMAP** Presenta varios scripts que contienen comandos SMTP, utiliza el comando HELLO para enumerar todos los comandos usables en el servicio. Uno de los scripts NSE mas importantes es el *smtp-open-relay* para identificar si el servicio es vulnerable a **mail relaying** a través de 16 pruebas (tal como se haría con MetasPloit) y el script *smtp-enum-users.nse* para enumerar posibles usuarios.  

``` bash
sudo nmap <IP> -p25 --script smtp-open-relay -v
```


### IMAP / POP3

Internet Message Access Protocol (**IMAP**) nos permite el acceso a correos electrónicos desde un servidor de correo. A diferencias de Post Office Protocol (**POP3**), IMAP permite la gestión de correos directamente en el servidor estructurándolos por carpetas.

POP3 solamente proporciona las funcionalidades de listado, recuperación y eliminación de correos.

Para **Establecer Conexión al Servidor** el cliente se conecta al servidor IMAP través del puerto *TCP 143* y para una conexión cifrada se conecta al servicio IMAPs a través del puerto *TCP 993*
Por otro lado, POP3 estable la conexión por el puerto *TCP 110* para comunicaciones regulares y  por el puerto *TCP 995* para comunicaciones cifradas por el servicio POP3s.

Para la comunicación usan comandos en formato *ASCII*. Esto son algunos de los comandos para interactuar con el servicio IMAP y POP3:

| Comandos **IMAP**       | Descripción                                      | Comandos **POP3** | Descripción                                     |
| ----------------------- | ------------------------------------------------ | ----------------- | ----------------------------------------------- |
| a LOGIN user pass       | Inicio de sesión en el servicio                  | USER user         | Identifica al usuario                           |
| a LIST "" *             | Enumera todos los directorios                    | PASS password     | Autentica al usuario                            |
| a CREATE/DELETE " "     | Crear o eliminar un buzón                        | STAT              | Despliega la cantidad de correos guardados      |
| a SELECT/UNSELECT INBOX | Seleccionar o salir de un buzón                  | LIST              | Solicita el ID y el tamaño de todos los correos |
| a FETCH 1:* (FLAGS)     | Despliega las flags para cada uno de los correos | RETR/DELE id      | Mostrar/borrar el correo solicitado por la IP   |
| a FETCH n BODY[]        | Despliega el correo con cabecera y cuerpo        | QUIT              | Cierra la conexión con el servidor POP3         |

#### Enumeración del servicio

Los servicios de IMAP y POP3 como sus variantes cifradas (IMAPs y POP3s) pueden ser enumerados de manera similar:

1. **NMAP:** Usando los NSE scripts de nmap podemos llegar a enumerar las capacidades del servidor y el CommonName.
2. **CURL:** Podemos logearnos al servicio de IMAPs mediante el comandos CURL haciendo uso de una sesión con credenciales conocidas.  

``` bash
# Enumera los buzones disponibles
curl -k 'imaps://<IP>' --user user:password
# Despliega mucha información acerca del servidor, como se establece la conección e informacion acerca del cifrado
curl -k 'imaps://<IP>' --user user:password -v
```  

#### Interacción y enumeración SSL

Para interactuar con el servidor SSL de IMAP y POP3 podemos usar la herramienta **openssl** y **ncat**. con los siguientes comandos:
``` bash
# POP3s
openssl s_client -connect <IP>:pop3s

# IMAPs
openssl s_client -connect <IP>:imaps
```

### Simple Network Management Protocol (SNMP)

Este es un protocolo creado para monitorear dispositivos de red, también se puede usar para realizar configuraciones de manera remota y manejar tareas de configuración. El hardware habilitado para SNMP incluye **routers**, **switches**, **servers**, **IoT devices**, entre otros.
Su ultima versión es SNMPv3 la misma que mejora mucho su seguridad pero también su complejidad de uso.

**SNMP** transmite comandos de control además de datos por el puerto *UDP 161*. En la comunicación clásica es el cliente quien solicita información al servidor, SNMP también permite el envió de paquetes *traps* a través del puerto *UDP 162*.

Algunos protocolos y características del servicio SNMP:

1. **MIB** (Management Information Based) es un protocolo desarrollado para garantizar que SNMP funcione para todos los fabricantes y con diferentes combinaciones de cliente-servidor. Los MIB no contienen información de datos, pero explican donde encontrar que información y como se ve.

2. **Ruta al archivo de configuración:** `/eyc/snmp/snmpd.conf`

3. **Identificador único** (OID) representa un nodo en un espacio de nombres jerárquicos. Es una secuencia de números que identifica de forma única a cada nodo.

4. **Community Strings** una especie de contraseñas que determinan si se puede o no ver la información solicitada. 


#### Enumeración del servicio

Existe varias herramientas como *snmp-check*, *snmpwalk*, *OneSixtyOne* y *braa*.

##### SNMP-CHECK
Da información organizada en información del sistema, de la red, procesos, aplicaciones, rutas del sistema.
``` bash
snmp-check <IP> [parametros]
```
##### SNMPWALK
Esta herramienta se utiliza para consultar los **OID** con su información, de estar mal configurado el servicio podremos extraer la cadena de comunidad (community strings) , y podremos acceder al servicio sin autentificación (solo para las versiones **snmpv1** y **v2c**).
``` bash
snmpwalk -v2c -c public <IP>
```

##### OneSixtyOne
Podemos extraer la información de la cadena de comunidad por fuerza fruta utilizando el diccionario snmp.txt de SecList. A menudo ciertas cadenas de la comunidad están vinculadas a ciertas direcciones IP especificas, e incluso se agregan símbolos para complicar el cifrado. Sin embargo, de ser una red grande podremos identificar ciertos patrones para los que podremos crear diccionarios personalizados con la herramienta [Crunch](https://www.kali.org/tools/crunch/)
``` bash
sudo apt install onesixtyone
onesixtyone -c community-strings-wordlist.txt <IP>
```

##### BRAA
Una vez que conocemos la cadena de la comunidad podemos usarla con braa para forzar los OID individuales y enumerar la información detrás de ellos.
``` bash
sudo apt install braa
braa <community string>@<IP>:.1.3.6.*
```

### MySQL

**MySQL** es un sistema de gestión de bases de datos relacionales SQL de código abierto y respaldado por Oracle. El sistema de bases de datos puede procesar rápidamente una gran cantidad de datos. El servidor MySQL es el sistema de gestión de bases de datos real. Se encarga del almacenamiento y distribución de datos en una estructura de tablas. Estas tablas se almacenan en un solo archivo de extensión *.sql*.

El servicio de MySQL se conecta comúnmente por el puerto *TCP 3306*.

#### Comando Básicos SQL 

| Comando                                                 | Descripción                                                       |
| ------------------------------------------------------- | ----------------------------------------------------------------- |
| show databases;                                         | Muestra todas la bases de datos alojadas en el servidor           |
| use < database >;                                       | Selecciona una de las bases de datos existentes                   |
| show tables;                                            | Muestra las tablas disponibles en la base de datos seleccionada   |
| show columns from < table >;                            | Muestra las columnas de una tabla                                 |
| select * from < table >;                                | Muestra todo de la tabla deseada                                  |
| select * from < table > where < column > = "< string>"; | Filtra el contenido de la tabla según se especifique en el string |

#### Enumeración e interacción con el servicio

Las bases de datos comúnmente requieren de una autentificación de usuario y contraseña, estos dos parámetros pueden ser encontrados por fuerza bruta si las credenciales son débiles mediante herramientas como [hydra](https://github.com/vanhauser-thc/thc-hydra). 

Podemos **enumerar** algunas características del servicio mediante los scripts NSE de **NMAP** de la siguiente menera:
``` bash
sudo nmap <IP> -sCV -p3306 --script mysql*
```

Para interactuar con el servicio utilizamos el siguiente comando:
``` bash
mysql -u <user> -p<password> -h <IP>

# Usar un archivo de extension .sql
mysql -u <user> -p<password> <Base de datos> < archivo.sql
```

### Microsoft SQL

**MSSQL** es un sistema de gestión de base de datos relacionales en SQL que a diferencia de MySQL esta es de código cerrado y se escribió inicialmente para sistemas operativos.

El **Cliente MSSQL** es gestionado por SQL Server Mangement Studio (SSMS) este es el nodo principal para la gestión del servidor y la configuración a corto y largo plazo

Puede configurarse mediante **Windows Authentication**, lo que significa que el sistema operativo Windows procederá la solicitud de inicio de sesión y utilizara la base de datos SAM o el controlador de dominio alojado en *Active Directory* antes de establecer la conexión. Haciendo que cuando se comprometa una cuenta esta se puede usar para el escalado de privilegios o un movimiento lateral en el entorno del dominio.

#### Enumeración del servicio

El servicio MSSQL corre normalmente por el puerto *TCP 1433* y podemos enumerarlo de las siguientes maneras:

1. Mediante **NMAP** podemos usar una larga cadena de scripts que que nos ayuden a ver el *hostname*, *database*, *instance name*, *software version* y *named pipes*. Con el siguiente comando:
``` bash
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p1433 <IP>
```

2. Por **Metasploit** podemos ejecutar un escáner auxiliar llamado *mssql_ping* que escaneara el servicio MSSQL y proporcionará información útil.
``` bash
msf6 auxiliary(scanner/mssql/mssql_ping) > set rhosts <IP>
msf6 auxiliary(scanner/mssql/mssql_ping) > run
```

3. Podemos usar el script de Python creado por impacket **mssqlclient.py** pre instalada en distribuciones Linux como Kali o Parrot. Esta herramienta sirve en caso hayamos logrado obtener credenciales para acceder al servicio de manera remota.
``` bash
python3 mssqlclient.py <user>@<IP> -windows-auth
```

### Oracle TNS

El servidor **Oracle Transparent Network Substrate** (TNS) es un sistema de comunicación entre bases de datos Oracle y aplicaciones a través de redes.
Este servicio tiene dos archivos básicos de configuración: *tnsnames.ora* y *listener.ora* encargados de ser transmisor y receptor del servicio respectivamente.

Este servicio corre por el puerto *TCP 1521*

Para este servicio son importantes los códigos únicos **SID** que son valores predeterminados para cada usuario que identifican una instancia de la base de datos en particular.

#### Enumeración del servicio

Al servicio lo podemos enumerar básicamente con 3 herramientas: **NMAP**, **ODAT** y **SQLcl** (básicamente porque sqlplus nunca me funciono)

##### NMAP
podemos hacer uso del script *oracle-sid-brute* para intentar descubrir el SID de algún usuario
``` bash
sudo nmap -p1521 -sV <IP> --script oracle-sid-brute
```
##### ODAT

Esta herramienta nos puede ayudar también a descubrir información sobre el servicio y sus componentes. Podemos recuperar nombres de bases de datos, versiones, procesos, cuentas de usuario, vulnerabilidades, ect. Con una mayor potencia que NMAP.  
Instalación:
``` bash
git clone https://github.com/quentinhardy/odat.git
cd odat/
git submodule init
git submodule update
```
Uso:
``` bash
# Desplegar panel de opciones
./odat.py -h

# Uso convencional
./odat.py all -s <IP>
```
##### SQLcl
Esta herramienta nos ayudara a establecer una conexión con el servicio, funciona de una manera muy similar a slqplus
Instalación: Descargamos el script de su pagina oficial de [Oracle](https://www.oracle.com/database/technologies/instant-client.html).  
Uso:
``` bash
# insgrsamos sin sessión
./sql /nolog

# Dentro de SQLcli
connect usuario/password@//host:puerto/servicio
```

### Intelligent Platform Management Interface (IPMI)

Es un conjunto de especificaciones para sistemas de administracion de host utilizados para el monitoreo del sistema. Funcionan independientemente de la BIOS, la CPU, el Firmware y el sistema operativo.

Tener el control de este protocolo es lo mas parecido al control físico del objetivo, pues nos permite gestionar el hardware, apagar el dispositivo, inhabilitar dispositivos de E/S, etc.

IPMI se comunica a través del puerto *UDP 623*. Los sistemas que usan el protocolo son llamados Baseboard Management Controllers (**BMC**). La mayoría de sistemas viene con un BMC o con la capacidad de adquirir uno, los mas comunes son: HP iLO, Dell DRAC y Supermicro IPMI.

#### Enumeración del servicio

**NMAP:** Podemos usar los scripts NSE para identificar la versión del servicio de la siguiente manera:
``` bash
sudo nmap -sU --script ipmi-version -p 623 <IP>
```

**Metasploit:** También podemos usar varios módulos de metasploit que nos permitan el análisis de la versión de la siguiente manera:
``` bash
msf6 > use auxiliary/scanner/ipmi/ipmi_version 
msf6 auxiliary(scanner/ipmi/ipmi_version) > set rhosts <IP>
msf6 auxiliary(scanner/ipmi/ipmi_version) > run
```
#### Obtención de Hashes

Para este servicio podemos encontrar que las contraseñas por defecto no han sido modificadas según los dispositivos antemencionados podemos probar las siguientes contraseñas:

| Marca           | User          | Password                         |
| --------------- | ------------- | -------------------------------- |
| Dell iDRAC      | root          | calvin                           |
| HP iLO          | Administrator | cadena aleatoria de 8 caracteres |
| Supermicro IPMI | ADMIN         | ADMIN                            |

Estas contraseñas pueden permitirnos acceder a la consola web del servicio o a la línea mediante SSH o Telnet.

Si las contraseñas anteriores no funcionan se puede recurrir a la falla en el protocolo RAKP en IPMI 2.0. Protocolo que envía un hash con la contraseña en SHA1 o MD5. Estos hash se pueden descifrar utilizando *Hashcat* en el modo 7300.

Para obtener los hashes de IPMI por fuerza bruta podemos usar el siguiente modulo de Metasploit:
``` bash
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes 
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set rhosts <IP>
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run
```

---

---

## **Remote Management Protocols**  

  
> El manejo remoto de dispositivos es esencial para realizar la administración o modificación de los servicios que puede brindar un sistema. Que se pueda hacer de manera remota supone un ahorro de tiempo al no ser necesario estar físicamente presente en el servidor y el entorno de trabajo sigue siendo el mismo, sin embargo abre la posibilidad de ser objetivos de atacantes en el caso de estar mal configurado.

### Linux

En Linux existe una gran variedad de maneras de conectarnos a un dispositivo de manera remota, estos son algunos de los protocolos, servidores y aplicaciones mas importantes

#### Secure Shell (SSH)

Este protocolo permite que dos ordenadores establezcan una conexión cifrada dentro de una red posiblemente insegura a través del puerto *TCP 22*. Existen dos protocolos:
SSH-2: Es el protocolo de SSH mas avanzado en seguridad, velocidad, estabilidad y cifrado.
SSH-1: Al ser mas antiguo es vulnerable a ataques Man In The Middle (**MITM**).

Existen 6 tipos de autentificación utilizadas por OpenSSH.
1. Por contraseña
2. Clave publica/privada
3. Basada en Host
4. Keyboard
5. Challenge-Response
6. GSSAPI

**Configuración predeterminada**
La configuración se aloja en la ruta `/etc/ssh/sshd_config`, no se recomienda la configuración predeterminada dado que puede tener una vulnerabilidad de inyección de comandos en la versión 7.2p1 en 2016.

#### Enumeración del servicio

Una de las herramientas que podemos utilizar es [ssh-audit](https://github.com/jtesta/ssh-audit) que comprueba la configuración del  lado del cliente y del servidor y muestra información general como el tipo de cifrado y que métodos de autentificación usa el servidor.
``` bash
git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit
./ssh-audit.py <IP>
```
Se puede forzar la conexión por contraseña para intentar ataques de fuerza bruta (si el servidor no lo permite dará un error)
``` bash
ssh -v <User>@<IP> -o PreferredAuthentications=password
```

#### Rsync

Esta es una herramienta rápida y eficiente para copiar archivos de manera local y remota. Es conocida por el su modo de transmisión delta, modo que optimiza la transferencia si en el lado del cliente existe una versión del archivo.
De manera predeterminada usa el puerto *TCP 873* y se puede configurar para utilizar SSH para una trasmisión segura.

Podemos ver algunas formas de enumerar el servicio en la wiki de [Hacktricks](https://book.hacktricks.wiki/en/network-services-pentesting/873-pentesting-rsync.html#873---pentesting-rsync).

#### Enumeración del servicio

Podemos acceder al servicio para ver a que ficheros o directorios podemos acceder
``` bash
nc -nv <IP> 873
#list
```
También podemos emplear el siguiente comando:
``` bash
rsync -av --list-only rsync://127.0.0.1/dev

# Si esta configurado para utilizar SSH
rsync -av --list-only -e "ssh -p2222" rsync://127.0.0.1/dev
```

#### R-Services

Son un conjunto de servicios para permitir el acceso remoto o emitir comandos entre hosts Unix a través de TCP/IP. Fueron los principales servicios hasta la llegada de SSH. Al igual que Telnet los R-Services transmiten la información a través de la red sin cifrarse.

Los ataques a este conjunto de servicios se extienden a través de los puertos *TCP 512*, *513* y *514* y solo son accesibles por programas conocidos como **r-commands**. La siguiente tabla proporciona una descripción acerca de los r-commands mas explotados:

| Comando | Demonio<br>del servicio | Puerto | Protocolo de<br>transporte | Descripción                                                                                                                                               |
| ------- | ----------------------- | ------ | -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| rcp     | rshd                    | 514    | Control de tráfico         | Copia un archivo o directorio de forma <br>bidireccional, funciona como el comando<br>*cp* en linux.                                                      |
| rsh     | rshd                    | 514    | Control de tráfico         | Abre una shell en una máquina remota sin<br>inicio de sesión depende de las entradas<br>en los archivos `/etc/host.equiv` y<br>.rhosts para la validación |
| rexec   | rexecd                  | 512    | Control de tráfico         | Permite ejecución de comandos de shell<br>en una maquina remota. Requiere<br>autentificación de User y Password.                                          |
| rlogin  | rlogind                 | 513    | Control de tráfico         | Permite iniciar sesión en un host remoto,<br>similar a telnet pero solo para hosts tipo<br>Unix.                                                          |

El archivo `hosts.equiv` contiene una lista de hosts de confianza y se utiliza para otorgar accesos a otros sistemas.

---
### Windows

La administración remota esta habilitada de manera predeterminada a partir de Windows Server 2016. Esta función incluye al protocolo WS-Management, diagnostico y control de Hardware del servidor.

los principales componentes utilizados para la gestión remota de Windows server y Windows son los siguientes:

#### Remote Desktop Protocol (RDP)

Este protocolo permite que los comandos de visualización y control se transmitan a través de la **interfaz** grafica de usuario cifrada por redes IP. Utiliza el puerto por defecto *TCP y UDP 3389*.
Para establecer conexión tanto el firewall de la red como el del servidor deben permitir conexiones del exterior. en caso de usar **NAT** se debe de usar la dirección IP publica.

#### Enumeración del servicio

Podemos identificar rápidamente mediante **NMAP** si NLA (Autentificación de nivel de Red) esta habilitado
``` bash
nmap -sV -sC <IP> -p3389 --script rdp*
```
Cisco CX Security Labs también desarrollo un script llamado [rdp-sec-check.pl](https://github.com/CiscoCXSecurity/rdp-sec-check) para identificar la configuración de seguridad del protocolo.
``` bash
# Instalación
sudo cpan
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check

# Uso
./rdp-sec-check.pl <IP>
```

#### Interacción con el servicio

Desde Linux podemos interactuar con el servicio mediante *xfreerdp*, *rdesktop* o *Remmina*.
``` bash
xfreerdp /u:<User> /p:"P455w0rd!" /v:<IP>
```

#### WinRM

Es un protocolo de administración remota integrado en Windows basado en línea de comandos, WinRM se comunica por los puertos *TPC 5986* y *5985* el primero usando HTTPS, ya que los puertos 80 y 443 se usaban anteriormente para esta tarea.
Se integra con Windows Remote Shell (**WinRS**) para ejecución de comandos.

#### Enumeración del servicio

En Linux podemos utilizar [evil-winrm](https://github.com/Hackplayers/evil-winrm) para acceder a uno o mas servidores remotos. En Windows basta con ejecutar Test-WsMan desde la PowerShell.
``` bash
evil-winrm -i <IP> -u <user> -p <Password>
```

#### Windows Management Instrumentation (WMI)

Permite el acceso de lectura y escritura a casi todas las configuraciones en los sistemas Windows, por ende es la interfaz mas critica en el entorno remoto. Se accede a través de la PowerShell, VBScript o la consola (WMIC).

#### Enumeración del servicio

La comunicación con el servicio se da por el puerto *TCP 135* y después de establecer la conexión, la comunicación se traslada a un puerto aleatorio. Se puede usar [wmiexec.py](https://github.com/fortra/impacket/blob/master/examples/wmiexec.py) de Impacket.
``` bash
/usr/share/doc/python3-impacket/examples/wmiexec.py <User>:"P455w0rD!"@<IP> "hostname"
```

---

---
## Referencias

[1] Sitios web de interés: [crt.sh](https://crt.sh/), [Domain.Glass](https://domain.glass/), [GrayHatWarfare](https://grayhatwarfare.com/)
