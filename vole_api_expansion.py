
import subprocess
import sys
import json
import os
import time

def obtener_perfil(filepath):

    try:
        perfil = ""
        res = subprocess.run(['vol.py', '-f', filepath, 'imageinfo', '--output', 'json'], capture_output=True)
        res = json.loads(res.stdout.decode('utf-8'))

        if res:
            perfil = res.get("rows")[0][0].split(',')[0]
            if perfil == "No suggestion (Instantiated with no profile)":
                perfil=""
        return perfil

    except:
        return perfil

def obtener_procesos(filepath,perfil):
    """
    :param filepath: dirección donde se encuentra alojado el fichero de memoria
    :param perfil: profile de la memoria
    :return: array de dos posiciones con una salida completa de la función y otra reducida
    """
    try:
        respuesta = []
        salidaReducida=""
        salidaCompleta=""
        res = subprocess.run(['vol.py', '-f', filepath, 'pslist', '--profile', perfil, '--output', 'json'],
                             capture_output=True)
        res = json.loads(res.stdout.decode('utf-8'))
        print(res)
        salidaCompleta = ' '.join(res.get("columns")) + "\n"
        salidaReducida = "La lista de procesos es la siguiente: \n"

        salidaReducida = salidaReducida+res.get("columns")[1]+" "+res.get("columns")[2]+"\n"


        for x in res.get("rows"):
            salidaCompleta = salidaCompleta + " " + hex(x[0]) + " " + x[1] + " " + str(x[2]) + " " + str(x[3]) + " " \
                             + str(x[4]) + " " + str(x[5]) + " " + str(x[6]) + " " + str(x[7])
            salidaCompleta = salidaCompleta + " " + x[8] + " " + x[9] + "\n"
            salidaReducida = salidaReducida + x[1] + " " + str(x[2])+"\n"

        respuesta.append(salidaCompleta)
        respuesta.append(salidaReducida)
        return respuesta

    except:
        print("Error")
        respuesta = []
        salidaReducida = "Error en la obtención de procesos"
        salidaCompleta = "Error"
        respuesta.append(salidaReducida)
        respuesta.append(salidaCompleta)
        return respuesta

def obtener_procesos_ocultos(filepath, perfil):
    """
        Se considera que un proceso esta oculto si no ha podido ser listado por plist pero si por psscan y thrdproc.
        Ademas debe cumplor que su tiempo de salida sera distinto de 0, ya que en otro caso el proceso habra acabado
        Para ello utlizaremos la función psxview que consulta los procesos desde 7 perspectivas distintas
        (Listado de procesos, exploración de objetos de proceso, escaneo de subproceso, subprocesos de escritorio,
         procesos de sesion, tabla de manejador CSRSS y tabla de manejador PspCid)
        En ocasiones los atacantes pueden obtener privilegios y accediendo al nucleo de memoria pueden sobrescribir el
        campo _EPROCESS.ExiTime para que aparezca como que ha salido.
        Una manera de detectarlo es que los procesos que han acabado no tienen subprocesos y ademas tienen un
        identificador no válido.

    :param filepath: dirección donde se encuentra alojado el fichero de memoria
    :param perfil: profile de la memoria
    :return: array de dos posiciones con una salida completa de la función y otra reducida
    """
    try:
        respuesta = []
        salidaReducida = ""
        salidaCompleta = ""
        pro_mod_exittime = ""
        res = subprocess.run(['vol.py', '-f', filepath, 'psxview', '--apply-rules', '--profile', perfil,
                              '--output', 'json'],capture_output=True)
        res = json.loads(res.stdout.decode('utf-8'))
        print(res)
        salidaCompleta=' '.join(res.get("columns"))+"\n"
        salidaReducida="Lista de posibles procesos ocultos:\n"
        salidaReducida=salidaReducida+res.get("columns")[1]+" "+res.get("columns")[2]+"\n"

        # Comprobación de si hay procesos intentando camuflarse cambiadno el tiempo de salida
        respslist = subprocess.run(['vol.py', '-f', filepath, 'pslist', '--profile', perfil, '--output', 'json'],
                                   capture_output=True)
        respslist = json.loads(respslist.stdout.decode('utf-8'))
        for x in res.get("rows"):
            if x[3] == 'False' and x[4] == 'True' and x[5] == 'True' and (x[10] == 0 or x[10] == ''):
                salidaCompleta=salidaCompleta+" "+ hex(x[0])+" "+x[1]+" "+str(x[2])+" "+x[3]+" "+x[4]+" "+x[5]+\
                               " "+x[6]+" "+x[7]
                salidaCompleta = salidaCompleta+" "+x[8]+" "+x[9]+" "+x[10]+"\n"
                salidaReducida=salidaReducida+x[1]+" "+str(x[2])+"\n"
            if x[10] != 0 and x[10] != '':
                for y in respslist.get("rows"):
                    if y[2] == x[2] and y[4] !=0:
                        pro_mod_exittime=pro_mod_exittime+x[1]+" "+str(x[2])+"\n"
        if pro_mod_exittime != "":
            salidaReducida=salidaReducida + "Procesos ocultos que han modificado el tiempo de salida de manera " \
                                            "fraudulenta:\n"
            salidaReducida = salidaReducida +pro_mod_exittime
        respuesta.append(salidaCompleta)
        respuesta.append(salidaReducida)

        return respuesta
    except:
        print("Error")
        respuesta = []
        salidaReducida = "Error en la obtención de procesos ocultos"
        salidaCompleta = "Error"
        respuesta.append(salidaReducida)
        respuesta.append(salidaCompleta)
        return respuesta

def obtener_procesos_criticos(filepath,perfil):
    """
        Devuelve solo los procesos criticos de los sistemas windows
    :param filepath: dirección donde se encuentra alojado el fichero de memoria
    :param perfil: profile de la memoria
    :return: array de dos posiciones con una salida completa de la función y otra reducida
    """
    try:
        respuesta = []
        salidaReducida = ""
        salidaCompleta = ""
        pro_mod_exittime = ""
        res = subprocess.run(['vol.py', '-f', filepath, 'pslist', '--profile', perfil,
                              '--output', 'json'], capture_output=True)
        res = json.loads(res.stdout.decode('utf-8'))
        print(res)
        salidaCompleta = ' '.join(res.get("columns")) + "\n"
        salidaReducida = "Lista de criticos:\n"
        salidaReducida = salidaReducida + res.get("columns")[1] + " " + res.get("columns")[2] + "\n"

        for x in res.get("rows"):
            if x[1] == 'Idle' or x[1] == 'System' or x[1] == 'csrss.exe' or x[1] == 'services.exe' or x[1] == \
                    'svchost.exe' or x[1] == 'lsass.exe' or x[1] == 'winlogon.exe' or x[1] == 'explorer.exe' \
                    or x[1] == 'smss.exe':
                salidaCompleta = salidaCompleta + " " + hex(x[0]) + " " + x[1] + " " + str(x[2]) + " " + str(x[3]) \
                        + " " + str(x[4]) + " " + str(x[5]) + " " + str(x[6]) + " " + str(x[7])+ " " + str(x[8]) \
                        + x[9] + "\n"
                salidaReducida = salidaReducida + x[1] + " " + str(x[2]) + "\n"

        respuesta.append(salidaCompleta)
        respuesta.append(salidaReducida)
        return respuesta

    except:
        print("Error")
        respuesta = []
        salidaReducida = "Error en la obtención de procesos criticos"
        salidaCompleta = "Error"
        respuesta.append(salidaReducida)
        respuesta.append(salidaCompleta)
        return respuesta

def obtener_dlls(filepath,perfil):
    """
        Devuelve las dlls asociados a procesos encontrados en el sistema
    :param filepath: dirección donde se encuentra alojado el fichero de memoria
    :param perfil: profile de la memoria
    :return: array de dos posiciones con una salida completa de la función y otra reducida
    """
    try:
        respuesta = []
        salidaReducida = ""
        salidaCompleta = ""

        res = subprocess.run(['vol.py', '-f', filepath, 'ldrmodules', '--profile', perfil,
                              '--output', 'json'], capture_output=True)
        res = json.loads(res.stdout.decode('utf-8'))
        print(res)
        salidaCompleta = ' '.join(res.get("columns")) + "\n"
        salidaReducida = "Lista de dlls asociadas a los procesos:\n"
        procesoAnterior=""
        for x in res.get("rows"):
            salidaCompleta = salidaCompleta + " " + str(x[0]) + " " + x[1] + " " + hex(x[2]) + " " + x[3] \
                             + " " + x[4] + " " + x[5] + " " + x[6] + "\n"
            if procesoAnterior != x[0]:
                salidaReducida = salidaReducida + "######## Dlls ocultas para el proceso " + x[1] + " ########\n"
                salidaReducida = salidaReducida + res.get("columns")[0] + " " + res.get("columns")[1] + " " + \
                                 res.get("columns")[6] + "\n"
                salidaReducida = salidaReducida + str(x[0]) + " " + x[1] + " " + x[6] + "\n"
            else:
                salidaReducida = salidaReducida + str(x[0]) + " " + x[1] + " " + x[6] + "\n"
            procesoAnterior = x[0]
        respuesta.append(salidaCompleta)
        respuesta.append(salidaReducida)
        return respuesta

    except:
        print("Error")
        respuesta = []
        salidaReducida = "Error en la obtención de dlls"
        salidaCompleta = "Error"
        respuesta.append(salidaReducida)
        respuesta.append(salidaCompleta)
        return respuesta

def obtener_dlls_ocultas(filepath,perfil):
    """
        Devuelve las dlls ocultas
        Si una dll muestra valor Falso para las tres columnas osea, no se encuentra en las listas del PEB, pero aun asi
        tiene asociado un path se considera que esta dll no se encuentra enlazada.
    :param filepath: dirección donde se encuentra alojado el fichero de memoria
    :param perfil: profile de la memoria
    :return: array de dos posiciones con una salida completa de la función y otra reducida
    """
    try:
        respuesta = []
        salidaReducida = ""
        salidaCompleta = ""

        res = subprocess.run(['vol.py', '-f', filepath, 'ldrmodules', '--profile', perfil,
                              '--output', 'json'], capture_output=True)
        res = json.loads(res.stdout.decode('utf-8'))
        print(res)
        salidaCompleta = ' '.join(res.get("columns")) + "\n"
        salidaReducida = "Lista de dlls ocultas:\n"
        procesoAnterior=""
        for x in res.get("rows"):
            if x[3] == "False" and x[4] == "False" and x[5] == "False" and x[6] != "":
                salidaCompleta = salidaCompleta + " " + str(x[0]) + " " + x[1] + " " + hex(x[2]) + " " + x[3] \
                                 + " " + x[4] + " " + x[5] + " " + x[6] + "\n"
                if procesoAnterior != x[0]:
                    salidaReducida = salidaReducida + "######## Dlls ocultas para el proceso " + x[1] + "########\n"
                    salidaReducida = salidaReducida + res.get("columns")[0] + " " + res.get("columns")[1] + " " + \
                                     res.get("columns")[6] + "\n"
                    salidaReducida = salidaReducida + str(x[0]) + " " + x[1] + " " + x[6] + "\n"
                else:
                    salidaReducida = salidaReducida + str(x[0]) + " " + x[1] + " " + x[6] + "\n"
                procesoAnterior = x[0]

        respuesta.append(salidaCompleta)
        respuesta.append(salidaReducida)
        return respuesta

    except:
        print("Error")
        respuesta = []
        salidaReducida = "Error en la obtención de dlls ocultas"
        salidaCompleta = "Error"
        respuesta.append(salidaReducida)
        respuesta.append(salidaCompleta)
        return respuesta

def obtener_privilegios_procesos(filepath,perfil):
    """
        Devuelve los privilegios asociados a los procesos, solo devolvera la lista de privilegios auto a
        signados por el proceso y no los que se asignan por defecto o herencia.
    :param perfil: profile de la memoria
    :return: array de dos posiciones con una salida completa de la función y otra reducida
    """
    try:
        respuesta = []
        salidaReducida = ""
        salidaCompleta = ""
        pid = ""
        pidanterior=""

        salidaReducida = "Devuelve los privilegios asociados a los procesos, solo muestra la lista de " \
                         "privilegios auto asignados por el proceso y no los que se asignan por defecto o herencia:\n"
        resProc = subprocess.run(['vol.py', '-f', filepath, 'pslist', '--profile', perfil,
                              '--output', 'json'], capture_output=True)
        resProc = json.loads(resProc.stdout.decode('utf-8'))
        salidaCompleta = "Pid Process Value  Privilege Attributes Description\n"
        for y in resProc.get("rows"):
            pid = str(y[2])
            res = subprocess.run(['vol.py', '-f', filepath, 'privs', '-p', pid,
                                 '--output', 'json'], capture_output=True)
            res = json.loads(res.stdout.decode('utf-8'))
            for x in res.get("rows"):
                if x[4] == "Present,Enabled":
                    if pid == pidanterior:
                        salidaReducida = salidaReducida + str(x[0]) + " " + x[3] + " " \
                                         + x[5] + "\n"
                    else:
                        salidaReducida = salidaReducida + "######## Privilegios auto asignados al proceso " + y[
                            1] + "########\n"
                        salidaReducida = salidaReducida + res.get("columns")[0] + " " + res.get("columns")[3] + " " \
                                         + res.get("columns")[5] + "\n"
                        salidaReducida = salidaReducida + str(x[0]) + " " + x[3] + " " \
                                         + x[5] + "\n"
                    salidaCompleta = salidaCompleta + str(x[0]) + " " + x[1] + " " + str(x[2]) + " " + x[3] \
                                     + " " + x[4] + " " + x[5] +"\n"
                    pidanterior = pid
        respuesta.append(salidaCompleta)
        respuesta.append(salidaReducida)
        return respuesta

    except:
        print("Error")
        respuesta = []
        salidaReducida = "Error en la obtención de privilegios de procesos"
        salidaCompleta = "Error"
        respuesta.append(salidaReducida)
        respuesta.append(salidaCompleta)
        return respuesta
def obtener_drivers(filepath):
    """
        Devuelve una lista de driver y la tabla IRP decada uno de ellos a fin de que se pueda comprobar si un driver
        llama a otro de manera ilegitima.
    :param filepath: direccion de la memoria
    :return: array de dos posiciones con una salida completa de la función y otra reducida
    """
    try:
        respuesta = []
        salidaReducida = ""
        salidaCompleta = ""

        salidaReducida = "Devuelve los driver cargados y su tabla IRP a fin de que se pueda detectar " \
                         "llamadas ilegitimas\n"
        res = subprocess.run(['vol.py', '-f', filepath, 'driverirp'], capture_output=True)
        res = res.stdout.decode('utf-8')
        posicion=res.find("DriverName")
        if posicion != -1:
            salidaReducida = salidaReducida + res[posicion:]
            salidaCompleta = res[posicion:]
        else:
            salidaReducida = "No se han obtenido drivers cargados"
            salidaCompleta = "No se han obtenido drivers cargados"

        respuesta.append(salidaCompleta)
        respuesta.append(salidaReducida)
        return respuesta

    except:
        print("Error")
        respuesta = []
        salidaReducida = "Error en la obtención de drivers cargados"
        salidaCompleta = "Error"
        respuesta.append(salidaReducida)
        respuesta.append(salidaCompleta)
        return respuesta

def obtener_registros_persistentes(filepath):
    """
        Devuelve procesos que potencialmente persisten en el sistema
    :param filepath: direccion de la memoria
    :return: array de dos posiciones con una salida completa de la función y otra reducida
    """
    try:
        respuesta = []
        salidaCompleta = "Registry KeyName KeyStability LastWrite Subkeys SubkeyStability ValType ValName" \
                                          " ValStability ValData\n"
        salidaReducida = "Devuelve una lista de procesos, ejecutables, dlls o drivers que tienen estableida " \
                         "persistencia dentro del sistema gracias a la modificacion de claves de registro \n"
        keys = ['Microsoft\Windows\CurrentVersion\RunOncen' , 'Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
                'Microsoft\Windows\CurrentVersion\Run', '\Microsoft\Windows NT\CurrentVersion\Windows',
                'Microsoft\Windows NT\CurrentVersion\Windows\Run', 'Microsoft\Windows\CurrentVersion\Run',
                'Microsoft\Windows\CurrentVersion\RunOnce']

        for key in keys:
            res = subprocess.run(['vol.py', '-f', filepath, 'printkey', '-K', key, '--output', 'json'],
                                 capture_output=True)
            res = json.loads(res.stdout.decode())
            if len(res.get("rows"))>0:
                primeravez=1
                for x in res.get("rows"):
                    if x[6] == 'REG_SZ' and x[9] != '-':
                        if primeravez:
                            salidaReducida = salidaReducida + "######################Persistencia en la clave " + key \
                                             +"######################\n"
                            salidaReducida = salidaReducida + res.get("columns")[0] + " " + res.get("columns")[1] +\
                                             " " +\
                                         res.get("columns")[3] + " " + res.get("columns")[7] + " " + \
                                             res.get("columns")[9] + "\n"
                            primeravez=0
                        salidaReducida = salidaReducida + x[0] + " " + x[1] + " " + x[3] + " " + x[7] + " " + x[9] \
                                         + "\n"
                        salidaCompleta = salidaCompleta + x[0] + " " + x[1] + " " + x[2] + " " + x[3] + " " + x[4]\
                                         + x[5] + " " + x[6] + " " + x[7] + " " + x[8] + " " + x[9] + "\n"

        salidaCompleta.replace('\x00', '')
        salidaReducida.replace('\x00', '')

        respuesta.append(salidaCompleta)
        respuesta.append(salidaReducida)
        return respuesta

    except:
        print("Error")
        respuesta = []
        salidaReducida = "Error en la obtención de procesos persistentes"
        salidaCompleta = "Error"
        respuesta.append(salidaReducida)
        respuesta.append(salidaCompleta)
        return respuesta

def obtener_servicios_persistentes(filepath, perfil):
    """
        Devuelve procesos que potencialmente persisten en el sistema por servicios
    :param filepath: direccion de la memoria
    :param perfil: perfil de la memoria
    :return: array de dos posiciones con una salida completa de la función y otra reducida
    """
    try:
        respuesta = []
        salidaCompleta = "Registry KeyName KeyStability LastWrite Subkeys SubkeyStability ValType ValName" \
                                          " ValStability ValData\n"
        salidaReducida = "Devuelve una lista de procesos, ejecutables, dlls o drivers que tienen estableida " \
                         "persistencia dentro del sistema gracias a la utilización de servicios\n"

        res = subprocess.run(['vol.py', '-f', filepath, 'printkey', '--profile', perfil,
                              '-K', 'currentcontrolset', '--output', 'json'], capture_output=True)
        res = json.loads(res.stdout.decode())
        controlset= ""
        if len(res.get("rows")) > 0:
            for y in res.get("rows"):
                if y[1] == "CurrentControlSet" and y[6] == "REG_LINK" and y[9] != "":
                    controlset= y[9]
                    posicioncurrentset= controlset.find("\ControlSet")
                    if posicioncurrentset != -1:
                        controlset= controlset[posicioncurrentset+1:]
                        print(controlset)
                    else:
                            controlset= ""
        if controlset != "":
            res = subprocess.run(['vol.py', '-f', filepath, 'printkey', '--profile', perfil,
                                  '-K', controlset+"\services", '--output', 'json'], capture_output=True)
            res = json.loads(res.stdout.decode())
            if len(res.get("rows")) > 0:
                for y in res.get("rows"):
                    if y[1] == "Services" and y[4] != "" and y[4] != "-":
                        servicio= y[4]
                        serviciocon = "\\"+servicio
                        resservico = subprocess.run(['vol.py', '-f', filepath, 'printkey', '--profile', perfil,
                                              '-K', controlset + "\services\\"+servicio, '--output', 'json'],
                                                    capture_output=True)
                        resservicio = json.loads(resservico.stdout.decode())
                        if len(resservicio.get("rows")) > 0:
                            primeravez = 1
                            for x in resservicio.get("rows"):
                                if x[6] == 'REG_SZ' and x[9] != '-':
                                    if primeravez:
                                        salidaReducida = salidaReducida + "######################Persistencia en el " \
                                                                          "servicio " + servicio \
                                                         + "######################\n"
                                        salidaReducida = salidaReducida + resservicio.get("columns")[0] + " " + \
                                                         resservicio.get("columns")[1] + " " + \
                                                         resservicio.get("columns")[3] + " " + \
                                                         resservicio.get("columns")[7] + " " + \
                                                         resservicio.get("columns")[9] + "\n"
                                        primeravez = 0
                                    salidaReducida = salidaReducida + x[0] + " " + x[1] + " " + x[3] + " " + x[
                                        7] + " " + x[9] + "\n"
                                    salidaCompleta = salidaCompleta + x[0] + " " + x[1] + " " + x[2] + " " + x[
                                        3] + " " + x[4] \
                                                     + x[5] + " " + x[6] + " " + x[7] + " " + x[8] + " " + x[9] + "\n"
        salidaCompleta.replace('\x00', '')
        salidaReducida.replace('\x00', '')

        respuesta.append(salidaCompleta)
        respuesta.append(salidaReducida)
        return respuesta

    except:
        print("Error")
        respuesta = []
        salidaReducida = "Error en la obtención de persistencia por servicios"
        salidaCompleta = "Error"
        respuesta.append(salidaReducida)
        respuesta.append(salidaCompleta)
        return respuesta

def obtener_historial_comandos_consola(filepath, perfil):
        """
            Devuelve el historial de comandos ejecutados por consola o a través de una puerta trasera
        :param filepath: direccion de la memoria
        :param perfil: perfil de la memoria
        :return: array de dos posiciones con una salida completa de la función y otra reducida
        """
        try:
            respuesta = []

            salidaReducida = "Devuelve el historial de comandos ejecutados por consola o a través de una puerta " \
                             "trasera\n"

            res = subprocess.run(['vol.py', '-f', filepath, 'consoles', '--profile', perfil], capture_output=True)
            res = res.stdout.decode()
            salidaCompleta = res

            res = subprocess.run(['vol.py', '-f', filepath, 'consoles', '--profile', perfil,
                                  '--output', 'json'], capture_output=True)
            res = json.loads(res.stdout.decode())
            if len(res.get("rows")) > 0:
                salidaReducida = salidaReducida + res.get("columns")[0] + " "+ res.get("columns")[1] + " "\
                               + res.get("columns")[22]+"\n"
                for y in res.get("rows"):
                    salidaReducida = salidaReducida + y[0] + " " + str(y[1]) + " " + y[22] + "\n"
            respuesta.append(salidaCompleta)
            respuesta.append(salidaReducida)
            return respuesta

        except:
            print("Error")
            respuesta = []
            salidaReducida = "Error en la obtención del historial de consola"
            salidaCompleta = "Error"
            respuesta.append(salidaReducida)
            respuesta.append(salidaCompleta)
            return respuesta


def obtener_conexiones_remotas(filepath, perfil):
    """
        Devuelve las conexiones remotas del sitema.
    :param filepath: direccion de la memoria
    :param perfil: perfil de la memoria
    :return: array de dos posiciones con una salida completa de la función y otra reducida
    """
    try:
        respuesta = []

        salidaReducida = "Devuelve las conexiones remotas del sistema\n"

        res = subprocess.run(['vol.py', '-f', filepath, 'connections', '--profile', perfil,
                              '--output', 'json'], capture_output=True)
        res = json.loads(res.stdout.decode())
        if len(res.get("rows")) > 0:
            salidaReducida = salidaReducida + res.get("columns")[3] + " " + res.get("columns")[1] + " " \
                             + res.get("columns")[2] + "\n"
            salidaCompleta = ' '.join(res.get("columns")) + "\n"
            for y in res.get("rows"):
                salidaReducida = salidaReducida + str(y[3]) + " " + y[1] + " " + y[2] + "\n"
                salidaCompleta = salidaCompleta + hex(y[0]) + " " + y[1] + " " + y[2] + " " + str(y[3]) + "\n"

        respuesta.append(salidaCompleta)
        respuesta.append(salidaReducida)
        return respuesta

    except:
        print("Error")
        respuesta = []
        salidaReducida = "Error en la obtención de las conexiones remotas"
        salidaCompleta = "Error"
        respuesta.append(salidaReducida)
        respuesta.append(salidaCompleta)
        return respuesta

def deteccion_red_modo_promiscuo(filepath, perfil):
    """
        Devuelve si existe alguna tarjeta de red en modo promiscuo.
    :param filepath: direccion de la memoria
    :param perfil: perfil de la memoria
    :return: array de dos posiciones con una salida completa de la función y otra reducida
    """
    try:
        respuesta = []
        salidaCompleta = ""
        salidaReducida = "Devuelve las tarjetas de red que se encuentren en modo promiscuo\n"

        res = subprocess.run(['vol.py', '-f', filepath, 'sockets', '--profile', perfil,
                              '--output', 'json'], capture_output=True)
        res = json.loads(res.stdout.decode())
        print(res)
        if len(res.get("rows")) > 0:
            primera = 1
            for y in res.get("rows"):
                if y[4] == "HOPOPT" and y[2] == 0:
                    if primera:
                        salidaReducida = salidaReducida + res.get("columns")[1] + " " + res.get("columns")[2] \
                                         + " " +res.get("columns")[4] + " " + res.get("columns")[5] + "\n"
                        salidaCompleta = ' '.join(res.get("columns")) + "\n"
                        primera = 0
                    salidaReducida = salidaReducida +  str(y[1]) + " " + str(y[2]) + " " + y[4] + " " + y[5] \
                                     + " " + y[6] + "\n"
                    salidaCompleta = salidaCompleta + hex(y[0]) + " " + str(y[1]) + " " + str(y[2]) + " " + str(y[3]) \
                                     + " " + y[4] + " " + y[5] + " " + y[6] + "\n"

        respuesta.append(salidaCompleta)
        respuesta.append(salidaReducida)
        return respuesta

    except:
        print("Error")
        respuesta = []
        salidaReducida = "Error en la obtención de tarjetas de red en modo promiscuo"
        salidaCompleta = "Error"
        respuesta.append(salidaReducida)
        respuesta.append(salidaCompleta)
        return respuesta

def obtener_conexiones_remotas_antiguas(filepath, perfil):
    """
        Devuelve las conexiones remotas antiguas del sistema.
    :param filepath: direccion de la memoria
    :param perfil: perfil de la memoria
    :return: array de dos posiciones con una salida completa de la función y otra reducida
    """
    try:
        respuesta = []

        salidaReducida = "Devuelve las conexiones remotas antiguas del sistema puede contener información parcial" \
                         "debido a la sobreescritura de información\n"

        res = subprocess.run(['vol.py', '-f', filepath, 'connections', '--profile', perfil,
                              '--output', 'json'], capture_output=True)
        res = json.loads(res.stdout.decode())
        print(res)

        resscan = subprocess.run(['vol.py', '-f', filepath, 'connscan', '--profile', perfil,
                              '--output', 'json'], capture_output=True)
        resscan = json.loads(resscan.stdout.decode())

        print(resscan)

        if len (resscan.get("rows")) > 0:
            salidaReducida = salidaReducida + res.get("columns")[3] + " " + res.get("columns")[1] + " " \
                             + res.get("columns")[2] + "\n"
            salidaCompleta = ' '.join(res.get("columns")) + "\n"
            for x in resscan.get("rows"):
                encontrado = 0
                if len(res.get("rows")) > 0:
                    for y in res.get("rows"):
                        if x[1] == y[1] and x[2] == y[2] and x[3] == y[3]:
                            encontrado= 1
                    if encontrado == 0:
                        salidaReducida = salidaReducida + str(x[3]) + " " + x[1] + " " + x[2] + "\n"
                        salidaCompleta = salidaCompleta + hex(x[0]) + " " + x[1] + " " + x[2] + " " + str(x[3]) + "\n"

        respuesta.append(salidaCompleta)
        respuesta.append(salidaReducida)
        return respuesta

    except:
        print("Error")
        respuesta = []
        salidaReducida = "Error en la obtención de las conexiones remotas"
        salidaCompleta = "Error"
        respuesta.append(salidaReducida)
        respuesta.append(salidaCompleta)
        return respuesta

def obtener_url_fuerza_bruta(filepath, perfil):
    """
        Devuelve las urls obtenidas que han sido consultadas por los navegadores encontrados en los procesos del
         sistema.
    :param filepath: direccion de la memoria
    :param perfil: perfil de la memoria
    :return: array de dos posiciones con una salida completa de la función y otra reducida
    """
    try:
        respuesta = []
        salidaCompleta=""
        salidaReducida = "Devuelve las urls obtenidas que han sido consultadas por los navegadores encontrados en " \
                         "los procesos del sistema. Salida no estructurada\n"

        res = subprocess.run(['vol.py', '-f', filepath, 'pslist', '--profile', perfil,
                              '--output', 'json'], capture_output=True)
        res = json.loads(res.stdout.decode('utf-8'))
        print(res)

        if len (res.get("rows")) > 0:

            for x in res.get("rows"):
                if x[1] == "iexplore.exe" or x[1] == "firefox.exe" or x[1] == "chrome.exe" or x[1] == "Chrome.exe" \
                        or x[1] == "Firefox.exe" or x[1] == "MicrosoftEdge.exe":
                    pid = str(x[2])
                    resurl = subprocess.run(['vol.py', '-f', filepath, 'yarascan', '-p', pid, '--profile', perfil, '-Y',
                                         "/(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}"
                                         "|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|"
                                         "(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})/"],
                                            capture_output=True)
                    resurl =resurl.stdout.decode()
                    print(resurl)
                    salidaCompleta = salidaCompleta + resurl
                    salidaReducida = salidaReducida + resurl

                    resurl = subprocess.run(['vol.py', '-f', filepath, 'yarascan', '-p', pid, '--profile', perfil, '-Y',
                                             "/[a-zA-Z0-9\-\.]+\.(com|org|net|mil|edu|biz|name|info)/"],
                                            capture_output=True)
                    resurl = resurl.stdout.decode()
                    print(resurl)
                    salidaCompleta = salidaCompleta + resurl
                    salidaReducida = salidaReducida + resurl

        respuesta.append(salidaCompleta)
        respuesta.append(salidaReducida)
        return respuesta

    except:
        print("Error")
        respuesta = []
        salidaReducida = "Error en la obtención de url por fuerza bruta"
        salidaCompleta = "Error"
        respuesta.append(salidaReducida)
        respuesta.append(salidaCompleta)
        return respuesta

def obtener_historial_iexplorer(filepath, perfil):
    """
        Devuelve el historial de internet explorer.
    :param filepath: direccion de la memoria
    :param perfil: perfil de la memoria
    :return: array de dos posiciones con una salida completa de la función y otra reducida
    """
    try:
        respuesta = []
        salidaCompleta=""
        salidaReducida = "Devuelve el historial de internet explorer. Salida no estructurada\n"

        res = subprocess.run(['vol.py', '-f', filepath, 'iehistory', '--profile', perfil], capture_output=True)
        res = res.stdout.decode('utf-8')
        salidaCompleta = res
        salidaReducida = salidaReducida + res


        respuesta.append(salidaCompleta)
        respuesta.append(salidaReducida)
        return respuesta

    except:
        print("Error")
        respuesta = []
        salidaReducida = "Error en la obtención del historia de internet explorer"
        salidaCompleta = "Error"
        respuesta.append(salidaReducida)
        respuesta.append(salidaCompleta)
        return respuesta

def recuperar_dns_cache(filepath):
    """
        Devuelve el contenido del archivo de DNS
    :param filepath: direccion de la memoria
    :return: array de dos posiciones con una salida completa de la función y otra reducida
    """
    try:
        respuesta = []
        salidaCompleta=""
        salidaReducida = "Devuelve el contenido del archivo de DNS\n"
        directorio =os.getcwd()
        directorioArchivoAntiguo = ""
        res = subprocess.run(['vol.py', '-f', filepath, 'filescan', '--output', 'json'], capture_output=True)
        res = json.loads(res.stdout.decode())
        if len (res.get("rows")) > 0:
            for x in res.get("rows"):
                posicion= x[4].find("\host")
                if posicion != -1:
                    direccion = hex(x[0])
                    sumary = "sumary" + str(x[0]) + ".txt"
                    res = subprocess.run(['vol.py', '-f', filepath, 'dumpfiles', '-Q', direccion, '-D',
                                          directorio, "-S", sumary],capture_output=True)
                    print(res)
                    rutasumary = directorio + "/" + sumary
                    contenido = ""
                    with open(rutasumary, "r") as archivo:
                        for linea in archivo.readlines():
                            contenido = contenido + linea

                    if contenido != "":
                        contjson = json.loads(contenido)
                        direccionArchivo = contjson["ofpath"]
                        if directorioArchivoAntiguo != direccionArchivo:
                            directorioArchivoAntiguo = direccionArchivo
                            with open(directorioArchivoAntiguo, "r") as archivo:
                                for linea in archivo.readlines():
                                    linea = linea.replace("\00", "")
                                    salidaCompleta = salidaCompleta + linea
                                    salidaReducida =salidaReducida + linea

        respuesta.append(salidaCompleta)
        respuesta.append(salidaReducida)
        return respuesta

    except:
        print("Error")
        respuesta = []
        salidaReducida = "Error en la obtención del contenido del archivo de DNS"
        salidaCompleta = "Error"
        respuesta.append(salidaReducida)
        respuesta.append(salidaCompleta)
        return respuesta

def extraer_todos_drivers(filepath, directorio):
    """
        Extrae las todas las dlls de la memoria
    :param filepath: direccion de la memoria
    :param directorio: direccion del export
    :return: array con una salida adaptada de la función
    """
    try:
        respuesta = []
        salidaCompleta=""
        res = subprocess.run(['vol.py', '-f', filepath, 'moddump', '-D',
                              directorio, '--output', 'json'],capture_output=True)
        res = json.loads(res.stdout.decode())
        print(res)

        if len (res.get("rows")) > 0:
            for x in res.get("rows"):
                salidaCompleta = salidaCompleta + "#############################################################\n"
                salidaCompleta = salidaCompleta + res.get("columns")[2] + " " + x[2] + " " \
                                 + res.get("columns")[1] + " " + x[1] \
                                 + " " + res.get("columns")[0] + ": " + hex(x[0]) +"\n"
        if salidaCompleta == "":
            salidaCompleta = "Error: No se ha podido realizar la extracción"

        respuesta.append(salidaCompleta)
        return respuesta

    except:
        print("Error")
        respuesta = []
        salidaCompleta = "Error: No se ha podido realizar la extracción"
        respuesta.append(salidaCompleta)
        return respuesta

def extraer_todas_dlls(filepath, directorio):
    """
        Extrae las todas las dlls de la memoria
    :param filepath: direccion de la memoria
    :param directorio: direccion del export
    :return: array con una salida adaptada de la función
    """
    try:
        respuesta = []
        salidaCompleta=""
        res = subprocess.run(['vol.py', '-f', filepath, 'dlldump', '-D',
                              directorio, '--output', 'json'],capture_output=True)
        res = json.loads(res.stdout.decode())
        print(res)

        if len (res.get("rows")) > 0:
            for x in res.get("rows"):
                salidaCompleta = salidaCompleta + "#############################################################\n"
                salidaCompleta = salidaCompleta + res.get("columns")[4] + " " + x[4] + " " \
                                 + res.get("columns")[1] + " " + x[1] \
                                 + " " + res.get("columns")[0] + ": " + hex(x[0]) \
                                 + " " + res.get("columns")[2] + ": " + hex(x[2]) \
                                 + " " + res.get("columns")[3] + ": " + x[3] + "\n"
        if salidaCompleta == "":
            salidaCompleta = "Error: No se ha podido realizar la extracción"

        respuesta.append(salidaCompleta)
        return respuesta

    except:
        print("Error")
        respuesta = []
        salidaCompleta = "Error: No se ha podido realizar la extracción"
        respuesta.append(salidaCompleta)
        return respuesta

def extraer_dlls_proceso(filepath, directorio, pid):
    """
        Extrae las todas las dlls de la memoria
    :param filepath: direccion de la memoria
    :param directorio: direccion del export
    :param pid: Pid del proceso asociado a las dlls
    :return: array con una salida adaptada de la función
    """
    try:
        respuesta = []
        salidaCompleta=""
        res = subprocess.run(['vol.py', '-f', filepath, 'dlldump', '--pid='+pid, '-D',
                                  directorio, '--output', 'json'],capture_output=True)
        res = json.loads(res.stdout.decode())
        print(res)
        if len (res.get("rows")) > 0:
            for x in res.get("rows"):
                salidaCompleta = salidaCompleta + "#############################################################\n"
                salidaCompleta = salidaCompleta + res.get("columns")[4] + " " + x[4] + " " \
                                     + res.get("columns")[1] + " " + x[1] \
                                     + " " + res.get("columns")[0] + ": " + hex(x[0]) \
                                     + " " + res.get("columns")[2] + ": " + hex(x[2]) \
                                     + " " + res.get("columns")[3] + ": " + x[3] + "\n"
        if salidaCompleta == "":
            salidaCompleta = "Error: No se ha podido realizar la extracción"

        respuesta.append(salidaCompleta)
        return respuesta

    except:
        print("Error")
        respuesta = []
        salidaCompleta = "Error: No se ha podido realizar la extracción"
        respuesta.append(salidaCompleta)
        return respuesta

def extraer_dlls_memoria(filepath, directorio, memoria):
    """
        Extrae las todas las dlls de la memoria
    :param filepath: direccion de la memoria
    :param directorio: direccion del export
    :param memoria: espacio de memoria asociado a las dlls
    :return: array con una salida adaptada de la función
    """
    try:
        respuesta = []
        salidaCompleta=""
        res = subprocess.run(['vol.py', '-f', filepath, 'dlldump', '-o', memoria, '-D',
                                  directorio, '--output', 'json'],capture_output=True)
        res = json.loads(res.stdout.decode())
        print(res)
        if len (res.get("rows")) > 0:
            for x in res.get("rows"):
                salidaCompleta = salidaCompleta + "#############################################################\n"
                salidaCompleta = salidaCompleta + res.get("columns")[4] + " " + x[4] + " " \
                                     + res.get("columns")[1] + " " + x[1] \
                                     + " " + res.get("columns")[0] + ": " + hex(x[0]) \
                                     + " " + res.get("columns")[2] + ": " + hex(x[2]) \
                                     + " " + res.get("columns")[3] + ": " + x[3] + "\n"
        if salidaCompleta == "":
            salidaCompleta = "Error: No se ha podido realizar la extracción"

        respuesta.append(salidaCompleta)
        return respuesta

    except:
        print("Error")
        respuesta = []
        salidaCompleta = "Error: No se ha podido realizar la extracción"
        respuesta.append(salidaCompleta)
        return respuesta

def obtener_voldado_hash_contrasena(filepath, directorio, perfil):
    """
        Extrae los hashes de las contraseñas almacenadas en el sistema windows
    :param filepath: direccion de la memoria
    :param directorio: direccion del export
    :param perfil: profile asociada ala memoria
    :return: array con una salida adaptada de la función
    """
    try:
        respuesta = []
        salidaCompleta=""
        res = subprocess.run(['vol.py', '-f', filepath, 'hashdump', '--profile', perfil],
                             capture_output=True)
        res = res.stdout.decode()
        if res != "" or res is not None:
            contienehash= res.find("No suitable address space mapping found")
            if contienehash == -1:
                salidaCompleta = "Se han extraido los siguientes hash relacionados con usuarios y contraseñas:\n"
                salidaCompleta = salidaCompleta + res +"\n"
                nmap_re = open("hash.txt", "w")
                nmap_re.write(res)
                nmap_re.close()
                res = subprocess.run(['john', '--show', "hash.txt"],capture_output=True)
                res = res.stdout.decode()
                errorobtenerpass= res.find("No password hashes left to crack")

                if errorobtenerpass == -1:
                    salidaCompleta = salidaCompleta + "############################################\n"
                    salidaCompleta = salidaCompleta + "Resultado despues del intento de desencriptado\n"
                    salidaCompleta = salidaCompleta + res +"\n"

                else:
                    salidaCompleta = salidaCompleta + "############################################\n"
                    salidaCompleta = salidaCompleta + "No se han podido desencriptar los hashes de las contraseñas encontradas\n"
                directorioguardar=directorio + "/hashpassword.txt"
                file = open(directorioguardar, "w")
                file.write(salidaCompleta)
                file.close()
            else:
                salidaCompleta = "El proceso no ha encontrado  ningun hash de contraseña\n"
        else:
            salidaCompleta = "El proceso no ha encontrado  ningun hash de contraseña\n"
        respuesta.append(salidaCompleta)
        return respuesta

    except:
        print("Error")
        respuesta = []
        salidaCompleta = "Error: No se ha podido realizar la extracción\n"
        respuesta.append(salidaCompleta)
        return respuesta