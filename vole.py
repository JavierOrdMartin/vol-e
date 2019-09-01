# -------
# vole.  Volatility for Studients
# -------
import tkinter as tk
import os
import vole_api_expansion as volapi
import yaml
from tkinter import ttk,messagebox
from tkinter import *
from tkinter import filedialog
from tkinter.filedialog import askopenfilename
from tkinter.font import Font
from tkinter.ttk import Combobox
import time
from tkinter import PhotoImage
from PIL import Image

import ast
import yaml

class vole(Frame):
    # ----------------
    # Elementos Estaticos
    # ----------------
    DEFPROCESO ='Un proceso es una unidad de actividad que se caracteriza por la ejecución de una secuencia de instrucciones, un estado actual, y un conjunto de recursos del sistema asociados'
    DEFRED = 'Un elemento de red es todo aquel elemento que guarda relación con la red de un sistema. por ejemplo socket, direcciones ips, puertos, firewall.'
    DEFMALWARE= 'Un elemento malware es todo tipo de programa o código informático malicioso cuya función es dañar un sistema o causar un mal funcionamiento'

    # ----------------
    # DefinicionInicial
    # ----------------

    def __init__(self):
        # Inicializacion de Variables:
        self.initVariables()
        
        self.raiz = Tk()
        self.raiz.geometry("430x200")
        self.raiz.resizable(0,0)
        self.raiz.title("Vole: Tu historia en el analisis de memoria")

        boton1= ttk.Button(self.raiz, text='Modo Historia (Principiante)', padding=(5,5),
                           command=self.ventana_modo_historia)
                           
        boton2= ttk.Button(self.raiz, text='Crea tu propio análisis (Avanzado)', padding=(5,5),
                           command=self.vetana_modo_experto)
        
        boton1.pack(side=TOP, fill=BOTH, expand=True, 
                         padx=5, pady=5)
        boton2.pack(side=TOP, fill=BOTH, expand=True, 
                         padx=5, pady=5)
        self.raiz.mainloop()
    # ----------------
    # Elementos GUI 
    # ----------------
    def initVariables(self):
        self.filePaths = None
        self.historiaSeleccionada = None
        self.directorioVoLe= os.getcwd()
        self.historias= []
        self.ventanaAnterior=""
        self.ventanaActual="raiz"
        self.modoEmpleo=None #1 para modo historia 2 para modo crear tu propia historia
        self.listaElementos=[]
        self.listaPreguntas=[]
        self.preguntaSeleccionada=0
        self.respuestaSeleccionada=5
        self.comandosProcesos = ["Listar Procesos", "Listar Procesos Ocultos", "Listar Procesos Criticos",
                                 "Listar Dlls Asociadas a Procesos", "Listar Dlls Ocultas",
                                 "Listar Privilegios auto-establecidos", "Listar Drivers y tabla IRP",
                                 "Listar Registros Persistentes", "Listar Persistencia por servicios",
                                 "Historial de comandos y consola"]
        self.comandosRed = ["Conexiones Remotas", "Tarjetas de Red en modo Promiscuo", "Conexiones Remotas Antiguas",
                            "Urls en procesos de navegadores", "Historial Internet Explorer", "Recuperar DNS Cache"]
        self.comandosMalware= ["Dll Ocultas"]
        self.comandosExtraer = ["Todas las Dlls", "Dlls Asociadas a Proceso", "Dll Espacio de Memoria",
                                "Todos los Drivers", "Obtener hash contraseñas"]
        self.metodoSeleccionado=""
        self.textSalidaProceso = ""
        self.textSalidaReducidaProceso= ""
        self.textSalidaRed = ""
        self.textSalidaReducidaRed= ""
        self.textSalidaMalware= ""
        self.textSalidaReducidaMalware= ""
        self.ultimoProcesoEjecutado=""
        self.ultimoRedEjecutado = ""
        self.ultimoMalwareEjecutado = ""
        self.reporteProcesos = ""
        self.reporteResumenProcesos = ""
        self.reporteRed = ""
        self.reporteResumenRed = ""
        self.irA=""
        self.profile = ""
        self.textoReporte = ""
        self.directorio_extraer= None

    def ventana_modo_historia(self):
        self.modoEmpleo = 1
        self.ventanaActual = "ventanaSeleccionarHistorias"
        # Definicion de la ventana del modo de seleccion de historia
        self.ventanaSeleccionModoHistoria = Toplevel()
        self.ventanaSeleccionModoHistoria.title("Seleccion de historias")
        fuente = Font(weight='bold')
        self.ventanaSeleccionModoHistoria.geometry("1080x720")
        self.ventanaSeleccionModoHistoria.resizable(0, 0)

        marco = ttk.Frame(self.ventanaSeleccionModoHistoria, borderwidth=2,
                          relief="raised", padding=(10, 10))

        etiq1 = ttk.Label(self.ventanaSeleccionModoHistoria, text="Selecciona una historia:",
                          font=fuente, )
        self.obtener_historias()
        self.combobox = Combobox(self.ventanaSeleccionModoHistoria, state="readonly", values=self.historias, width=30)

        self.combobox.bind("<<ComboboxSelected>>", self.selection_changed)

        scrollbar = tk.Scrollbar(marco)
        self.textDescripcionHistoria = Text(marco, height=20, width=100, wrap=WORD)
        self.textDescripcionHistoria.config(state="disabled")
        botonComenzar = ttk.Button(self.ventanaSeleccionModoHistoria, text='Comenzar',
                                   command=self.validar_comenzar_historia_seleccionada)

        etiq1.pack(side=TOP, padx=5, pady=40)
        self.combobox.pack(side=TOP, padx=5)
        marco.pack(side=TOP, pady=40)
        scrollbar.pack(side=RIGHT)
        self.textDescripcionHistoria.pack(side=LEFT, padx=5)
        scrollbar.config(command=self.textDescripcionHistoria.yview)
        self.textDescripcionHistoria.config(yscrollcommand=scrollbar.set)
        botonComenzar.pack()

        self.ventanaSeleccionModoHistoria.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.ventanaSeleccionModoHistoria.transient(master=self.raiz)
        self.ventanaSeleccionModoHistoria.grab_set()
        self.raiz.wait_window(self.ventanaSeleccionModoHistoria)

    def ventana_procesos(self):
        self.ventanaActual = "ventanaProcesos"
        self.ventanaProcesos = Toplevel()
        self.listaElementos = []
        self.preguntaSeleccionada = 0
        self.ventanaProcesos.title("Analisis de procesos historia: "+self.historiaSeleccionada)
        self.ventanaProcesos.resizable(0, 0)
        marco = tk.Frame(self.ventanaProcesos, borderwidth=2,
                              relief="raised", bg="#f37f66")

        img = tk.Image("photo", file=self.directorioVoLe+"/icons/info.png")
        botonInfo= tk.Button(marco, image=img, state="normal", text="info", bg="#f37f66",
                                               command=self.mostrar_info)
        etiq1 = tk.Label(marco, text="Informacion sobre elemento seleccionado:", bg="#f37f66",font='Helvetica 14 bold')
        self.textInfo = Text(marco, height=4, width=90, wrap=WORD)
        self.textInfo.config(state="disabled")
        scrollbar = tk.Scrollbar(marco)
        etiq2 = tk.Label(marco, text="Procesos, dlls, elementos importantes",bg="#f37f66", font='Helvetica 14 bold')
        self.listbox = tk.Listbox(marco)
        scrollbar2 = tk.Scrollbar(marco)
        marco2= tk.Frame(self.ventanaProcesos, borderwidth=2, relief="raised", bg="#f37f66")
        etiq3 = tk.Label(marco2, text="Pregunta:",bg="#f37f66",font='Helvetica 14 bold')
        self.textPregunta = Text(marco2, height=4, width=100, wrap=WORD)
        self.textPregunta.config(state="disabled")
        scrollbar3 = tk.Scrollbar(marco2)
        self.etiq4 = tk.Label(marco2, text="", bg="#f37f66")

        self.insertar_info_listbox()
        self.listbox.bind("<<ListboxSelect>>", self.onlist_boxclick)

        self.valorRespuesta = IntVar()
        self.radiobutton1 = tk.Radiobutton(marco2, text="Option 1", variable=self.valorRespuesta, value=1, bg="#f37f66",
                                           command=self.obtener_respuesta_seleccionada)
        self.radiobutton2 = Radiobutton(marco2, text="Option 2", variable=self.valorRespuesta, value=2, bg="#f37f66",
                                        command=self.obtener_respuesta_seleccionada)
        self.radiobutton3 = Radiobutton(marco2, text="Option 3", variable=self.valorRespuesta, value=3, bg="#f37f66",
                                        command=self.obtener_respuesta_seleccionada)
        self.radiobutton4 = Radiobutton(marco2, text="Option 4", variable=self.valorRespuesta, value=4, bg="#f37f66",
                                        command=self.obtener_respuesta_seleccionada)
        self.botonValidarRespuesta = tk.Button(marco2, state="disabled", text="Comprobar",
                                               command=self.validar_respuesta, bg="#f37f66")
        self.botonSiguientePregunta = tk.Button(marco2, state="disabled", text="Siguiente Pregunta",
                                                command=self.cambiar_pregunta, bg="#f37f66")

        self.recuperar_preguntas()
        self.insertar_pregunta()

        marco.grid(column=0, row=0)
        marco2.grid(column=0, row=4)
        etiq1.grid(column=0, row=1)
        etiq2.grid(column=2, row=1)
        botonInfo.grid(column=3,row=1)
        self.textInfo.grid(padx=20, pady=5, column=0, row=2)
        scrollbar.grid(ipadx=10, column=1, row=2)
        scrollbar.config(command=self.textInfo.yview)
        self.textInfo.config(yscrollcommand=scrollbar.set)
        self.listbox.grid(column=2, row=2, pady=20)
        scrollbar2.grid(ipadx=10, column=3, row=2, padx=20)
        scrollbar2.config(command=self.listbox.yview)
        self.listbox.config(yscrollcommand=scrollbar2.set)
        marco2.grid(column=0, row=4, sticky=N+S+E+W)
        etiq3.grid(column=0, row=0)
        self.textPregunta.grid(padx=20, pady=5, column=0, row=2)
        scrollbar3.grid(ipadx=10, column=1, row=2)
        scrollbar3.config(command=self.textPregunta.yview)
        self.textPregunta.config(yscrollcommand=scrollbar3.set)
        self.radiobutton1.grid(column=0, row=3)
        self.radiobutton2.grid(column=0, row=4)
        self.radiobutton3.grid(column=0, row=5)
        self.radiobutton4.grid(column=0, row=6)
        self.etiq4.grid(column=0, row=7)
        self.botonValidarRespuesta.grid(pady=10, column=0, row=8)
        self.botonSiguientePregunta.grid(pady=5, column=0, row=9)

        self.ventanaProcesos.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.ventanaProcesos.transient(master=self.raiz)
        self.ventanaProcesos.grab_set()
        self.raiz.wait_window(self.ventanaProcesos)

    def ventana_red(self):
        self.ventanaActual = "ventanaRed"
        self.ventanaRed = Toplevel()
        self.listaElementos =[]
        self.preguntaSeleccionada=0

        self.ventanaRed.title("Analisis de red historia: " + self.historiaSeleccionada)
        self.ventanaRed.resizable(0, 0)
        marco = tk.Frame(self.ventanaRed, borderwidth=2,
                             relief="raised", bg="#b4a22f")

        img = tk.Image("photo", file=self.directorioVoLe + "/icons/info.png")
        botonInfo = tk.Button(marco, image=img, state="normal", text="info", bg="#b4a22f",
                              command=self.mostrar_info)
        etiq1 = tk.Label(marco, text="Informacion sobre elemento de red seleccionado:",
                         font='Helvetica 14 bold', bg="#b4a22f")
        self.textInfo = Text(marco, height=4, width=90, wrap=WORD)
        self.textInfo.config(state="disabled")
        scrollbar = tk.Scrollbar(marco)
        etiq2 = tk.Label(marco, text="Red", font='Helvetica 14 bold', bg="#b4a22f")
        self.listbox = tk.Listbox(marco)
        scrollbar2 = tk.Scrollbar(marco)
        marco2 = tk.Frame(self.ventanaRed, borderwidth=2, relief="raised", bg="#b4a22f")
        etiq3 = tk.Label(marco2, text="Pregunta:", font='Helvetica 14 bold', bg="#b4a22f")
        self.textPregunta = Text(marco2, height=4, width=100, wrap=WORD)
        self.textPregunta.config(state="disabled")
        scrollbar3 = tk.Scrollbar(marco2)
        self.etiq4 = tk.Label(marco2, text="", bg="#b4a22f")

        self.insertar_info_listbox()
        self.listbox.bind("<<ListboxSelect>>", self.onlist_boxclick)

        self.valorRespuesta = IntVar()
        self.radiobutton1 = tk.Radiobutton(marco2, text="Option 1", variable=self.valorRespuesta, value=1,
                                               bg="#b4a22f", command=self.obtener_respuesta_seleccionada)
        self.radiobutton2 = Radiobutton(marco2, text="Option 2", variable=self.valorRespuesta, value=2,
                                            bg="#b4a22f", command=self.obtener_respuesta_seleccionada)
        self.radiobutton3 = Radiobutton(marco2, text="Option 3", variable=self.valorRespuesta, value=3,
                                            bg="#b4a22f", command=self.obtener_respuesta_seleccionada)
        self.radiobutton4 = Radiobutton(marco2, text="Option 4", variable=self.valorRespuesta, value=4,
                                            bg="#b4a22f", command=self.obtener_respuesta_seleccionada)
        self.botonValidarRespuesta = tk.Button(marco2, state="disabled", text="Comprobar",
                                                   command=self.validar_respuesta, bg="#b4a22f")
        self.botonSiguientePregunta = tk.Button(marco2, state="disabled", text="Siguiente Pregunta",
                                                    command=self.cambiar_pregunta, bg="#b4a22f")
        self.recuperar_preguntas()
        self.insertar_pregunta()

        marco.grid(column=0, row=0)
        marco2.grid(column=0, row=4)
        etiq1.grid(column=0, row=1)
        etiq2.grid(column=2, row=1)
        botonInfo.grid(column=3, row=1)
        self.textInfo.grid(padx=20, pady=5, column=0, row=2)
        scrollbar.grid(ipadx=10, column=1, row=2)
        scrollbar.config(command=self.textInfo.yview)
        self.textInfo.config(yscrollcommand=scrollbar.set)
        self.listbox.grid(column=2, row=2, pady=20)
        scrollbar2.grid(ipadx=10, column=3, row=2, padx=20)
        scrollbar2.config(command=self.listbox.yview)
        self.listbox.config(yscrollcommand=scrollbar2.set)
        marco2.grid(column=0, row=4, sticky=N + S + E + W)
        etiq3.grid(column=0, row=0)
        self.textPregunta.grid(padx=20, pady=5, column=0, row=2)
        scrollbar3.grid(ipadx=10, column=1, row=2)
        scrollbar3.config(command=self.textPregunta.yview)
        self.textPregunta.config(yscrollcommand=scrollbar3.set)
        self.radiobutton1.grid(column=0, row=3)
        self.radiobutton2.grid(column=0, row=4)
        self.radiobutton3.grid(column=0, row=5)
        self.radiobutton4.grid(column=0, row=6)
        self.etiq4.grid(column=0, row=7)
        self.botonValidarRespuesta.grid(pady=10, column=0, row=8)
        self.botonSiguientePregunta.grid(pady=5, column=0, row=9)

        self.ventanaRed.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.ventanaRed.transient(master=self.raiz)
        self.ventanaRed.grab_set()
        self.raiz.wait_window(self.ventanaRed)

    def ventana_malware(self):
        self.ventanaActual = "ventanaMalware"
        self.ventanaMalware = Toplevel()
        self.listaElementos = []
        self.preguntaSeleccionada = 0
        self.ventanaMalware.title("Analisis de malware historia: " + self.historiaSeleccionada)
        self.ventanaMalware.resizable(0, 0)
        marco = tk.Frame(self.ventanaMalware, borderwidth=2,
                             relief="raised", bg="#2fb45c")

        img = tk.Image("photo", file=self.directorioVoLe + "/icons/info.png")
        botonInfo = tk.Button(marco, image=img, state="normal", text="info", bg="#2fb45c",
                              command=self.mostrar_info)
        etiq1 = tk.Label(marco, text="Informacion sobre posible información malware seleccionado:",
                         font='Helvetica 14 bold', bg="#2fb45c")
        self.textInfo = Text(marco, height=4, width=90, wrap=WORD)
        self.textInfo.config(state="disabled")
        scrollbar = tk.Scrollbar(marco)
        etiq2 = tk.Label(marco, text="Información susceptible de malware", font='Helvetica 14 bold', bg="#2fb45c")
        self.listbox = tk.Listbox(marco)
        scrollbar2 = tk.Scrollbar(marco)
        marco2 = tk.Frame(self.ventanaMalware, borderwidth=2, relief="raised", bg="#2fb45c")
        etiq3 = tk.Label(marco2, text="Pregunta:", font='Helvetica 14 bold', bg="#2fb45c")
        self.textPregunta = Text(marco2, height=4, width=100, wrap=WORD)
        self.textPregunta.config(state="disabled")
        scrollbar3 = tk.Scrollbar(marco2)
        self.etiq4 = tk.Label(marco2, text="", bg="#2fb45c")

        self.insertar_info_listbox()
        self.listbox.bind("<<ListboxSelect>>", self.onlist_boxclick)

        self.valorRespuesta = IntVar()
        self.radiobutton1 = tk.Radiobutton(marco2, text="Option 1", variable=self.valorRespuesta, value=1,
                                               bg="#2fb45c", command=self.obtener_respuesta_seleccionada)
        self.radiobutton2 = Radiobutton(marco2, text="Option 2", variable=self.valorRespuesta, value=2,
                                            bg="#2fb45c", command=self.obtener_respuesta_seleccionada)
        self.radiobutton3 = Radiobutton(marco2, text="Option 3", variable=self.valorRespuesta, value=3,
                                            bg="#2fb45c", command=self.obtener_respuesta_seleccionada)
        self.radiobutton4 = Radiobutton(marco2, text="Option 4", variable=self.valorRespuesta, value=4,
                                            bg="#2fb45c", command=self.obtener_respuesta_seleccionada)
        self.botonValidarRespuesta = tk.Button(marco2, state="disabled", text="Comprobar",
                                                   command=self.validar_respuesta, bg="#2fb45c")
        self.botonSiguientePregunta = tk.Button(marco2, state="disabled", text="Siguiente Pregunta",
                                                    command=self.cambiar_pregunta, bg="#2fb45c")

        self.recuperar_preguntas()
        self.insertar_pregunta()

        marco.grid(column=0, row=0)
        marco2.grid(column=0, row=4)
        etiq1.grid(column=0, row=1)
        etiq2.grid(column=2, row=1)
        botonInfo.grid(column=3, row=1)
        self.textInfo.grid(padx=20, pady=5, column=0, row=2)
        scrollbar.grid(ipadx=10, column=1, row=2)
        scrollbar.config(command=self.textInfo.yview)
        self.textInfo.config(yscrollcommand=scrollbar.set)
        self.listbox.grid(column=2, row=2, padx=20)
        scrollbar2.grid(ipadx=10, column=3, row=2, padx=20)
        scrollbar2.config(command=self.listbox.yview)
        self.listbox.config(yscrollcommand=scrollbar2.set)
        marco2.grid(column=0, row=4, sticky=N + S + E + W)
        etiq3.grid(column=0, row=0)
        self.textPregunta.grid(padx=20, pady=5, column=0, row=2)
        scrollbar3.grid(ipadx=10, column=1, row=2)
        scrollbar3.config(command=self.textPregunta.yview)
        self.textPregunta.config(yscrollcommand=scrollbar3.set)
        self.radiobutton1.grid(column=0, row=3)
        self.radiobutton2.grid(column=0, row=4)
        self.radiobutton3.grid(column=0, row=5)
        self.radiobutton4.grid(column=0, row=6)
        self.etiq4.grid(column=0, row=7)
        self.botonValidarRespuesta.grid(pady=10, column=0, row=8)
        self.botonSiguientePregunta.grid(pady=5, column=0, row=9)

        self.ventanaMalware.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.ventanaMalware.transient(master=self.raiz)
        self.ventanaMalware.grab_set()
        self.raiz.wait_window(self.ventanaMalware)

    def ventana_conclusion(self):
        self.ventanaActual = "ventanaConclusion"
        self.ventanaConclusion = Toplevel()
        self.listaElementos = []
        self.preguntaSeleccionada = 0
        self.ventanaConclusion.title("Conclusiones de la historia: " + self.historiaSeleccionada)
        self.ventanaConclusion.resizable(0, 0)
        marco = tk.Frame(self.ventanaConclusion, borderwidth=2,relief="raised", bg="#2f6ab4")
        etiq1 = tk.Label(marco, text="Conclusiones:", bg="#2f6ab4")
        self.textInfo = Text(marco, height=40, width=90, wrap=WORD)
        self.textInfo.config(state="disabled")
        scrollbar = tk.Scrollbar(marco)
        self.botonFinalizar = tk.Button(marco, text="Finalizar", command=self.finalizar_historia, bg="#2f6ab4")

        self.insertar_conclusiones()

        marco.grid(column=0, row=0)
        etiq1.grid(column=0, row=0)
        self.textInfo.grid(padx=5, pady=5, column=0, row=1)
        scrollbar.grid(ipadx=10, column=1, row=1)
        scrollbar.config(command=self.textInfo.yview)
        self.textInfo.config(yscrollcommand=scrollbar.set)
        self.botonFinalizar.grid(pady=5, column=0, row=2)

        self.ventanaConclusion.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.ventanaConclusion.transient(master=self.raiz)
        self.ventanaConclusion.grab_set()
        self.raiz.wait_window(self.ventanaConclusion)

    def vetana_modo_experto(self):
        self.modoEmpleo = 2
        self.ventanaActual = "ventanaModoExperto"
        self.ventanaModoExperto = Toplevel()
        self.ventanaModoExperto.title("Crea tu propio análisis")
        self.ventanaModoExperto.resizable(0, 0)

        marco = ttk.Frame(self.ventanaModoExperto, borderwidth=2,
                          relief="raised", padding=(10, 10))

        self.textDireccionArchivo = Text(marco, height=1, width=20, wrap=WORD)
        self.textDireccionArchivo.config(state="disabled")

        boton0 = ttk.Button(marco, text=":", padding=(5, 5), width=5, command=self.buscar_directorio_archivo)
        self.etiqError = tk.Label(marco, text="")

        self.botonAnalisisProcesoE = tk.Button(marco, text="Analisis Procesos", command=self.ventana_procesos_experto,
                                               bg="#f37f66")
        self.botonAnalizarRedE = tk.Button(marco, text="Analisis Red", command=self.ventana_red_experto, bg="#b4a22f")
        #self.botonAnalizarMalware = tk.Button(marco, text="Analisis Malware", command=self.ventana_malware_experto,
         #                                     bg="#2fb45c")
        self.botonGenerarRepore = tk.Button(marco, text="Reporte", command=self.ventana_reporte, bg='#2f6ab4')
        self.botonGenerarExtraer = tk.Button(marco, text="Extraer", command=self.ventana_extraer, bg='#17cbe4')
        self.habilitar_desbotonera_modo_experto()

        marco.grid(column=0, row=0)
        self.textDireccionArchivo.grid(padx=5, pady=5, column=1, row=1, columnspan=3)
        boton0.grid(padx=5, pady=5, column=4, row=1)
        self.etiqError.grid(column=1, row=2)
        self.botonAnalisisProcesoE.grid(padx=5, pady=5, column=1, row=3, columnspan=4)
        self.botonAnalizarRedE.grid(padx=5, pady=5, column=1, row=4, columnspan=4)
        #self.botonAnalizarMalware.grid(padx=5, pady=5, column=1, row=5, columnspan=4)
        self.botonGenerarExtraer.grid(padx=5, pady=5, column=1, row=6, columnspan=4)
        self.botonGenerarRepore.grid(padx=5, pady=5, column=1, row=7, columnspan=4)

        self.ventanaModoExperto.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.ventanaModoExperto.transient(master=self.raiz)
        self.ventanaModoExperto.grab_set()
        self.raiz.wait_window(self.ventanaModoExperto)

    def ventana_procesos_experto(self):
        self.ventanaActual = "ventanaProcesosExpertos"
        self.ventanaProcesosExpertos = Toplevel()
        self.ventanaProcesosExpertos.title("Analisis de procesos")

        self.ventanaProcesosExpertos.resizable(0, 0)

        marco = tk.Frame(self.ventanaProcesosExpertos, borderwidth=2,
                         relief="raised", bg="#f37f66")
        etiq1 = tk.Label(marco, text="Lista de analisis:", bg="#f37f66")
        self.combobox = Combobox(marco, state="readonly", values=self.comandosProcesos, width=30)
        self.combobox.bind("<<ComboboxSelected>>", self.selection_proceso_changed)
        self.botonEjecutar = tk.Button(marco, text="Ejecutar", command=self.ejecutar_proceso,
                                               bg="#f37f66", state="disabled")
        etiq2 = tk.Label(marco, text="", bg="#f37f66")
        self.notebook = ttk.Notebook(marco)
        self.textSalida = Text(self.notebook, height=40, width=100, wrap=WORD)
        self.textSalidaReducida = Text(self.notebook, height=40, width=100, wrap=WORD)
        self.textSalida.config(state="disabled")
        self.textSalidaReducida.config(state="disabled")

        self.notebook.add(self.textSalidaReducida, text="Resumen", padding=20)
        self.notebook.add(self.textSalida, text="Output", padding=20)

        etiq3 = tk.Label(marco, text="Ir a:", bg="#f37f66")
        values = ["Analisis Red", "Extraer", "Reporte"]
        self.combobox2 = Combobox(marco, state="readonly", values=values, width=30)
        self.combobox2.bind("<<ComboboxSelected>>", self.selection_ventana_changed)
        self.botonIrA = tk.Button(marco, text="IR", command=self.ejecutar_ir_a,
                                       bg="#f37f66", state="disabled")

        self.comprobar_info_anterior()

        marco.grid(column=0, row=0)
        etiq1.grid(column=1,row=0)
        self.combobox.grid(column=2, row=0, columnspan=2)
        self.botonEjecutar.grid(column=5, row=0)
        self.notebook.grid(padx=20, column=0, row=1,columnspan=10, rowspan=10)
        etiq2.grid(column=0, row=20, columnspan=10, rowspan=10)
        etiq3.grid(column=1, row=21)
        self.combobox2.grid(column=2, row=21)
        self.botonIrA.grid(column=3, row=21)

        self.ventanaProcesosExpertos.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.ventanaProcesosExpertos.transient(master=self.ventanaModoExperto)
        self.ventanaProcesosExpertos.grab_set()
        self.ventanaModoExperto.wait_window(self.ventanaProcesosExpertos)

    def ventana_red_experto(self):
        self.ventanaActual = "ventanaRedExpertos"
        self.ventanaRedExpertos = Toplevel()
        self.ventanaRedExpertos.title("Analisis de red")

        self.ventanaRedExpertos.resizable(0, 0)

        marco = tk.Frame(self.ventanaRedExpertos, borderwidth=2,
                         relief="raised", bg="#b4a22f")
        etiq1 = tk.Label(marco, text="Lista de analisis:", bg="#b4a22f")
        self.combobox = Combobox(marco, state="readonly", values=self.comandosRed, width=30)
        self.combobox.bind("<<ComboboxSelected>>", self.selection_proceso_changed)
        self.botonEjecutar = tk.Button(marco, text="Ejecutar", command=self.ejecutar_proceso,
                                               bg="#b4a22f", state="disabled")
        etiq2 = tk.Label(marco, text="", bg="#b4a22f")
        self.notebook = ttk.Notebook(marco)
        self.textSalida = Text(self.notebook, height=40, width=100, wrap=WORD)
        self.textSalidaReducida = Text(self.notebook, height=40, width=100, wrap=WORD)
        self.textSalida.config(state="disabled")
        self.textSalidaReducida.config(state="disabled")

        self.notebook.add(self.textSalidaReducida, text="Resumen", padding=20)
        self.notebook.add(self.textSalida, text="Output", padding=20)

        etiq3 = tk.Label(marco, text="Ir a:", bg="#b4a22f")
        values = ["Analisis Procesos", "Extraer", "Reporte"]
        self.combobox2 = Combobox(marco, state="readonly", values=values, width=30)
        self.combobox2.bind("<<ComboboxSelected>>", self.selection_ventana_changed)
        self.botonIrA = tk.Button(marco, text="IR", command=self.ejecutar_ir_a,
                                  bg="#b4a22f", state="disabled")

        self.comprobar_info_anterior()

        marco.grid(column=0, row=0)
        etiq1.grid(column=1,row=0)
        self.combobox.grid(column=2, row=0, columnspan=2)
        self.botonEjecutar.grid(column=5, row=0)
        self.notebook.grid(padx=20, column=0, row=1,columnspan=10, rowspan=10)
        etiq2.grid(column=0, row=20, columnspan=10, rowspan=10)
        etiq3.grid(column=1, row=21)
        self.combobox2.grid(column=2, row=21)
        self.botonIrA.grid(column=3, row=21)

        self.ventanaRedExpertos.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.ventanaRedExpertos.transient(master=self.ventanaModoExperto)
        self.ventanaRedExpertos.grab_set()
        self.ventanaModoExperto.wait_window(self.ventanaRedExpertos)

    def ventana_malware_experto(self):
        self.ventanaActual = "ventanaMalwareExpertos"
        self.ventanaMalwareExpertos = Toplevel()
        self.ventanaMalwareExpertos.title("Analisis de posible Malware")

        self.ventanaMalwareExpertos.resizable(0, 0)

        marco = tk.Frame(self.ventanaMalwareExpertos, borderwidth=2,
                         relief="raised", bg="#2fb45c")
        etiq1 = tk.Label(marco, text="Lista de analisis:", bg="#2fb45c")
        self.combobox = Combobox(marco, state="readonly", values=self.comandosMalware, width=30)
        self.combobox.bind("<<ComboboxSelected>>", self.selection_proceso_changed)
        self.botonEjecutar = tk.Button(marco, text="Ejecutar", command=self.ejecutar_proceso,
                                               bg="#2fb45c", state="disabled")
        etiq2 = tk.Label(marco, text="", bg="#2fb45c")
        self.notebook = ttk.Notebook(marco)
        self.textSalida = Text(self.notebook, height=40, width=100, wrap=WORD)
        self.textSalidaReducida = Text(self.notebook, height=40, width=100, wrap=WORD)
        self.textSalida.config(state="disabled")
        self.textSalidaReducida.config(state="disabled")

        self.notebook.add(self.textSalidaReducida, text="Resumen", padding=20)
        self.notebook.add(self.textSalida, text="Output", padding=20)

        etiq3 = tk.Label(marco, text="Ir a:", bg="#2fb45c")
        values = ["Analisis Procesos", "Analisis Red", "Extraer", "Reporte"]
        self.combobox2 = Combobox(marco, state="readonly", values=values, width=30)
        self.combobox2.bind("<<ComboboxSelected>>", self.selection_ventana_changed)
        self.botonIrA = tk.Button(marco, text="IR", command=self.ejecutar_ir_a,
                                  bg="#2fb45c", state="disabled")

        self.comprobar_info_anterior()

        marco.grid(column=0, row=0)
        etiq1.grid(column=1,row=0)
        self.combobox.grid(column=2, row=0)
        self.botonEjecutar.grid(column=3, row=0)
        self.notebook.grid(padx=20, column=0, row=1,columnspan=10, rowspan=10)
        etiq2.grid(column=0, row=20, columnspan=10, rowspan=10)
        etiq3.grid(column=1, row=21)
        self.combobox2.grid(column=2, row=21)
        self.botonIrA.grid(column=3, row=21)

        self.ventanaMalwareExpertos.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.ventanaMalwareExpertos.transient(master=self.ventanaModoExperto)
        self.ventanaMalwareExpertos.grab_set()
        self.ventanaModoExperto.wait_window(self.ventanaMalwareExpertos)

    def ventana_extraer(self):
        self.ventanaActual = "ventanaExtraer"
        self.ventanaExtraer = Toplevel()
        self.ventanaExtraer.title("Extraer")

        self.ventanaExtraer.resizable(0, 0)

        marco = tk.Frame(self.ventanaExtraer, borderwidth=2,
                         relief="raised", bg="#17cbe4")
        etiq1 = tk.Label(marco, text="Lista de funcionalidades:", bg="#17cbe4")
        self.combobox = Combobox(marco, state="readonly", values=self.comandosExtraer, width=30)
        self.combobox.bind("<<ComboboxSelected>>", self.selection_proceso_changed)
        self.botonEjecutar = tk.Button(marco, text="Ejecutar", command=self.obtener_directorio_extraer,
                                               bg="#17cbe4", state="disabled")
        etiq2 = tk.Label(marco, text="", bg="#17cbe4")
        self.textSalida = Text(marco, height=20, width=50, wrap=WORD)
        self.textSalida.config(state="disabled")
        self.etiqparametros = tk.Label(marco, text="", bg="#17cbe4")

        etiq3 = tk.Label(marco, text="Ir a:", bg="#17cbe4")
        self.textparametro = Entry(marco)
        self.textparametro.config(state="disabled")

        values = ["Analisis Procesos", "Analisis Red", "Reporte"]
        self.combobox2 = Combobox(marco, state="readonly", values=values, width=30)
        self.combobox2.bind("<<ComboboxSelected>>", self.selection_ventana_changed)
        self.botonIrA = tk.Button(marco, text="IR", command=self.ejecutar_ir_a,
                                  bg="#17cbe4", state="disabled")

        self.comprobar_info_anterior()

        marco.grid(column=0, row=0)
        etiq1.grid(column=1,row=0,padx=20, pady=20)
        self.combobox.grid(column=2, row=0,padx=20, pady=20)
        self.botonEjecutar.grid(column=3, row=0, padx=20, pady=20)
        self.etiqparametros.grid(column=1, row=1, padx=20, pady=20)
        self.textparametro.grid(column=2, row=1, pady=20)
        self.textSalida.grid(padx=20, column=0, row=5,columnspan=10, rowspan=10)
        etiq2.grid(column=0, row=20, columnspan=10, rowspan=10)
        etiq3.grid(column=1, row=21)
        self.combobox2.grid(column=2, row=21)
        self.botonIrA.grid(column=3, row=21)

        self.ventanaExtraer.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.ventanaExtraer.transient(master=self.ventanaModoExperto)
        self.ventanaExtraer.grab_set()
        self.ventanaModoExperto.wait_window(self.ventanaExtraer)

    def ventana_reporte(self):
        self.ventanaActual = "ventanaReporte"
        self.ventanaReporte = Toplevel()
        self.ventanaReporte.resizable(0, 0)

        marco = tk.Frame(self.ventanaReporte, borderwidth=2,
                         relief="raised", bg="#2f6ab4")
        etiq1 = tk.Label(marco, text="Reporte:", bg="#2f6ab4")

        self.botonGuardar= tk.Button(marco, text="Guardar", command=self.guardar_reporte,
                                       bg="#2f6ab4")

        self.textSalidaReporte= Text(marco, height=40, width=100, wrap=WORD)
        self.textSalidaReporte.config(state="disabled")


        etiq3 = tk.Label(marco, text="Ir a:", bg="#2f6ab4")
        values = ["Analisis Procesos", "Analisis Red", "Extraer"]
        self.combobox2 = Combobox(marco, state="readonly", values=values, width=30)
        self.combobox2.bind("<<ComboboxSelected>>", self.selection_ventana_changed)
        self.botonIrA = tk.Button(marco, text="IR", command=self.ejecutar_ir_a,
                                  bg="#2f6ab4", state="disabled")

        self.comprobar_info_anterior()

        marco.grid(column=0, row=0)
        etiq1.grid(column=1, row=0, columnspan=2)
        self.botonGuardar.grid(column=3, row=0)
        self.textSalidaReporte.grid(column=0, row=1, columnspan=4, padx=20, pady=20)
        etiq3.grid(column=1, row=21)
        self.combobox2.grid(column=2, row=21, pady=20)
        self.botonIrA.grid(column=3, row=21, pady=20)

        self.ventanaReporte.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.ventanaReporte.transient(master=self.ventanaModoExperto)
        self.ventanaReporte.grab_set()
        self.ventanaModoExperto.wait_window(self.ventanaReporte)

    #------------------
    # Funcionalidades
    #------------------
    def mostrar_info(self):
        if self.ventanaActual == "ventanaProcesos":
            self.ventanaAnterior = "ventanaProcesos"
            self.ventanaActual = "ventanaInfo"
            self.ventanaInfo = Toplevel()
            self.ventanaInfo.resizable(0, 0)
            marco=tk.Frame(self.ventanaInfo, borderwidth=2,
                               relief="raised")
            textDefinicion = Text(marco, height=4, width=100, wrap=WORD)
            textDefinicion.config(state="normal")
            textDefinicion.insert(INSERT, vole.DEFPROCESO)
            textDefinicion.config(state="disabled")
            marco.grid(column=0, row=0)
            textDefinicion.grid(padx=5, pady=5, column=0, row=0, columnspan=4)

            self.ventanaInfo.protocol("WM_DELETE_WINDOW", self.on_closing)
            self.ventanaInfo.transient(master=self.ventanaProcesos)
            self.ventanaInfo.grab_set()
            self.ventanaProcesos.wait_window(self.ventanaInfo)
        elif self.ventanaActual == "ventanaRed":
            self.ventanaAnterior = "ventanaRed"
            self.ventanaActual = "ventanaInfo"
            self.ventanaInfo = Toplevel()
            marco=tk.Frame(self.ventanaInfo, borderwidth=2,
                               relief="raised")
            textDefinicion = Text(marco, height=4, width=100, wrap=WORD)
            textDefinicion.config(state="normal")
            textDefinicion.insert(INSERT, vole.DEFRED)
            textDefinicion.config(state="disabled")
            marco.grid(column=0, row=0)
            textDefinicion.grid(padx=5, pady=5, column=0, row=0, columnspan=4)

            self.ventanaInfo.protocol("WM_DELETE_WINDOW", self.on_closing)
            self.ventanaInfo.transient(master=self.ventanaRed)
            self.ventanaInfo.grab_set()
            self.ventanaRed.wait_window(self.ventanaInfo)
        elif self.ventanaActual == "ventanaMalware":
            self.ventanaAnterior = "ventanaMalware"
            self.ventanaActual = "ventanaInfo"
            self.ventanaInfo = Toplevel()
            marco=tk.Frame(self.ventanaInfo, borderwidth=2,
                               relief="raised")
            textDefinicion = Text(marco, height=4, width=100, wrap=WORD)
            textDefinicion.config(state="normal")
            textDefinicion.insert(INSERT, vole.DEFRED)
            textDefinicion.config(state="disabled")
            marco.grid(column=0, row=0)
            textDefinicion.grid(padx=5, pady=5, column=0, row=0, columnspan=4)

            self.ventanaInfo.protocol("WM_DELETE_WINDOW", self.on_closing)
            self.ventanaInfo.transient(master=self.ventanaMalware)
            self.ventanaInfo.grab_set()
            self.ventanaMalware.wait_window(self.ventanaInfo)

    def comprobar_info_anterior(self):
        if self.ventanaActual == "ventanaProcesosExpertos":
            if self.ultimoProcesoEjecutado !="":
                self.metodoSeleccionado = self.ultimoProcesoEjecutado
                self.textSalida.config(state="normal")
                self.textSalida.delete(1.0, END)
                self.textSalida.update()
                self.textSalida.insert(INSERT, self.textSalidaProceso)
                self.textSalida.insert(END, "")
                self.textSalida.config(state="disabled")

                self.textSalidaReducida.config(state="normal")
                self.textSalidaReducida.delete(1.0, END)
                self.textSalidaReducida.update()
                self.textSalidaReducida.insert(INSERT,  self.textSalidaReducidaProceso)
                self.textSalidaReducida.insert(END, "")
                self.textSalida.config(state="disabled")

                self.botonEjecutar.config(state="normal")
                posicionUltimoMetodo=self.comandosProcesos.index(self.ultimoProcesoEjecutado)
                self.combobox.current(posicionUltimoMetodo)
            else:
                self.metodoSeleccionado = self.ultimoProcesoEjecutado
                self.textSalida.config(state="normal")
                self.textSalida.delete(1.0, END)
                self.textSalida.update()
                self.textSalida.insert(INSERT, "")
                self.textSalida.insert(END, "")
                self.textSalida.config(state="disabled")

                self.textSalidaReducida.config(state="normal")
                self.textSalidaReducida.delete(1.0, END)
                self.textSalidaReducida.update()
                self.textSalidaReducida.insert(INSERT, "")
                self.textSalidaReducida.insert(END, "")
                self.textSalida.config(state="disabled")

        elif self.ventanaActual == "ventanaRedExpertos":
            if self.ultimoRedEjecutado != "":
                self.metodoSeleccionado= self.ultimoRedEjecutado
                self.textSalida.config(state="normal")
                self.textSalida.delete(1.0, END)
                self.textSalida.update()
                self.textSalida.insert(INSERT, self.textSalidaRed )
                self.textSalida.insert(END, "")
                self.textSalida.config(state="disabled")

                self.textSalidaReducida.config(state="normal")
                self.textSalidaReducida.delete(1.0, END)
                self.textSalidaReducida.update()
                self.textSalidaReducida.insert(INSERT, self.textSalidaReducidaRed)
                self.textSalidaReducida.insert(END, "")
                self.textSalida.config(state="disabled")

                self.botonEjecutar.config(state="normal")
                posicionUltimoMetodo=self.comandosRed.index(self.ultimoRedEjecutado)
                self.combobox.current(posicionUltimoMetodo)
            else:
                self.textSalida.config(state="normal")
                self.textSalida.delete(1.0, END)
                self.textSalida.update()
                self.textSalida.insert(INSERT, "")
                self.textSalida.insert(END, "")
                self.textSalida.config(state="disabled")

                self.textSalidaReducida.config(state="normal")
                self.textSalidaReducida.delete(1.0, END)
                self.textSalidaReducida.update()
                self.textSalidaReducida.insert(INSERT, "")
                self.textSalidaReducida.insert(END, "")
                self.textSalida.config(state="disabled")
        elif self.ventanaActual == "ventanaMalwareExpertos":
            if self.ultimoMalwareEjecutado != "":
                self.metodoSeleccionado = self.ultimoMalwareEjecutado
                self.textSalida.config(state="normal")
                self.textSalida.delete(1.0, END)
                self.textSalida.update()
                self.textSalida.insert(INSERT, self.textSalidaMalware)
                self.textSalida.insert(END, "")
                self.textSalida.config(state="disabled")

                self.textSalidaReducida.config(state="normal")
                self.textSalidaReducida.delete(1.0, END)
                self.textSalidaReducida.update()
                self.textSalidaReducida.insert(INSERT,  self.textSalidaReducidaMalware)
                self.textSalidaReducida.insert(END, "")
                self.textSalida.config(state="disabled")

                self.botonEjecutar.config(state="normal")
                posicionUltimoMetodo=self.comandosMalware.index(self.ultimoMalwareEjecutado)
                self.combobox.current(posicionUltimoMetodo)
            else:
                self.textSalida.config(state="normal")
                self.textSalida.delete(1.0, END)
                self.textSalida.update()
                self.textSalida.insert(INSERT, "")
                self.textSalida.insert(END, "")
                self.textSalida.config(state="disabled")

                self.textSalidaReducida.config(state="normal")
                self.textSalidaReducida.delete(1.0, END)
                self.textSalidaReducida.update()
                self.textSalidaReducida.insert(INSERT, "")
                self.textSalidaReducida.insert(END, "")
                self.textSalida.config(state="disabled")
        elif self.ventanaActual == "ventanaReporte":
                self.textoReporte = "################### Reporte " + self.filePaths + " ##################\n"
                self.textoReporte = self.textoReporte + "############ Resumen #############\n\n"
                if self.reporteResumenProcesos != "":
                    self.textoReporte = self.textoReporte + " ####### Funciones Procesos ######## \n"
                    self.textoReporte = self.textoReporte + self.reporteResumenProcesos
                if self.reporteResumenRed != "":
                    self.textoReporte = self.textoReporte + "####### Funciones Red ########\n"
                    self.textoReporte = self.textoReporte + self.reporteResumenRed
                self. textoReporte = self.textoReporte + "\n############# Salida Completa #############\n\n"
                if self.reporteProcesos != "":
                    self.textoReporte = self.textoReporte + "####### Funciones Procesos ########\n"
                    self.textoReporte = self.textoReporte + self.reporteProcesos
                if self.reporteRed != "":
                    self.textoReporte = self.textoReporte + "####### Funciones Red ########\n"
                    self.textoReporte = self.textoReporte + self.reporteRed
                self.textSalidaReporte.config(state="normal")
                self.textSalidaReporte.delete(1.0, END)
                self.textSalidaReporte.update()
                self.textSalidaReporte.insert(INSERT, self.textoReporte)
                self.textSalidaReporte.insert(END, "")
                self.textSalidaReporte.config(state="disabled")

    def guardar_reporte(self):
        f = filedialog.asksaveasfile(parent=self.ventanaReporte, mode='w', defaultextension=".txt")
        if f is not None:
            f.write(self.textoReporte)
            f.close()

    def obtener_directorio_extraer(self):
        self.directorio_extraer = filedialog.askdirectory(parent=self.ventanaExtraer)
        if self.directorio_extraer is not None and self.directorio_extraer != "":
            self.textSalida.config(state="normal")
            self.textSalida.delete(1.0, END)
            self.textSalida.update()
            self.textSalida.insert(INSERT, "Proceso de Extracción en curso")
            self.textSalida.insert(END, "")
            self.textSalida.update()
            self.textSalida.config(state="disabled")
            self.ejecutar_proceso()

    def ejecutar_ir_a(self):
        if self.irA != "":
            if self.ventanaActual == "ventanaProcesosExpertos":
                if self.irA == "Analisis Red":
                    self.ventanaProcesosExpertos.destroy()
                    self.ventana_red_experto()
                elif self.irA == "Analisis Malware":
                    self.ventanaProcesosExpertos.destroy()
                    self.ventana_malware_experto()
                elif self.irA == "Reporte":
                    self.ventanaProcesosExpertos.destroy()
                    self.ventana_reporte()
                elif self.irA == "Extraer":
                    self.ventanaProcesosExpertos.destroy()
                    self.ventana_extraer()
            elif self.ventanaActual == "ventanaRedExpertos":
                if self.irA == "Analisis Procesos":
                    self.ventanaRedExpertos.destroy()
                    self.ventana_procesos_experto()
                elif self.irA == "Analisis Malware":
                    self.ventanaRedExpertos.destroy()
                    self.ventana_malware_experto()
                elif self.irA == "Reporte":
                    self.ventanaRedExpertos.destroy()
                    self.ventana_reporte()
                elif self.irA == "Extraer":
                    self.ventanaRedExpertos.destroy()
                    self.ventana_extraer()
            elif self.ventanaActual == "ventanaMalwareExpertos":
                if self.irA == "Analisis Red":
                    self.ventanaMalwareExpertos.destroy()
                    self.ventana_red_experto()
                elif self.irA == "Analisis Procesos":
                    self.ventanaMalwareExpertos.destroy()
                    self.ventana_procesos_experto()
                elif self.irA == "Reporte":
                    self.ventanaMalwareExpertos.destroy()
                    self.ventana_reporte()
                elif self.irA == "Extraer":
                    self.ventanaMalwareExpertos.destroy()
                    self.ventana_extraer()
            elif self.ventanaActual == "ventanaReporte":
                if self.irA == "Analisis Procesos":
                    self.ventanaReporte.destroy()
                    self.ventana_procesos_experto()
                elif self.irA == "Analisis Red":
                    self.ventanaReporte.destroy()
                    self.ventana_red_experto()
                elif self.irA == "Analisis Malware":
                    self.ventanaReporte.destroy()
                    self.ventana_malware_experto()
                elif self.irA == "Extraer":
                    self.ventanaReporte.destroy()
                    self.ventana_extraer()
            elif self.ventanaActual == "ventanaExtraer":
                if self.irA == "Analisis Procesos":
                    self.ventanaExtraer.destroy()
                    self.ventana_procesos_experto()
                elif self.irA == "Analisis Red":
                    self.ventanaExtraer.destroy()
                    self.ventana_red_experto()
                elif self.irA == "Analisis Malware":
                    self.ventanaExtraer.destroy()
                    self.ventana_malware_experto()
                elif self.irA == "Reporte":
                    self.ventanaExtraer.destroy()
                    self.ventana_reporte()

    def ejecutar_proceso(self):
        if self.ventanaActual == "ventanaProcesosExpertos" or self.ventanaActual == "ventanaRedExpertos" \
                or self.ventanaActual == "ventanaMalwareExpertos":
            self.textSalidaReducida.config(state="normal")
            self.textSalidaReducida.delete(1.0, END)
            self.textSalidaReducida.update()
            self.textSalidaReducida.insert(INSERT, "Proceso en curso")
            self.textSalidaReducida.insert(END, "")
            self.textSalidaReducida.update()
            self.textSalidaReducida.config(state="disabled")
        #Funciones de procesos
        if self.metodoSeleccionado == "Listar Procesos":
            respuesta = volapi.obtener_procesos(self.filePaths, self.profile)
        elif self.metodoSeleccionado == "Listar Procesos Ocultos":
            respuesta = volapi.obtener_procesos_ocultos(self.filePaths, self.profile)
        elif self.metodoSeleccionado == "Listar Procesos Criticos":
            respuesta = volapi.obtener_procesos_criticos(self.filePaths, self.profile)
        elif self.metodoSeleccionado == "Listar Dlls Asociadas a Procesos":
            respuesta = volapi.obtener_dlls(self.filePaths, self.profile)
        elif self.metodoSeleccionado == "Listar Dlls Ocultas":
            respuesta = volapi.obtener_dlls_ocultas(self.filePaths, self.profile)
        elif self.metodoSeleccionado == "Listar Privilegios auto-establecidos":
            respuesta = volapi.obtener_privilegios_procesos(self.filePaths, self.profile)
        elif self.metodoSeleccionado == "Listar Drivers y tabla IRP":
            respuesta = volapi.obtener_drivers(self.filePaths)
        elif self.metodoSeleccionado == "Listar Registros Persistentes":
            respuesta = volapi.obtener_registros_persistentes(self.filePaths)
        elif self.metodoSeleccionado == "Listar Persistencia por servicios":
            respuesta = volapi.obtener_servicios_persistentes(self.filePaths, self.profile)
        elif self.metodoSeleccionado == "Historial de comandos y consola":
            respuesta = volapi.obtener_historial_comandos_consola(self.filePaths, self.profile)
        # Funciones de Red
        elif self.metodoSeleccionado == "Conexiones Remotas":
            respuesta = volapi.obtener_conexiones_remotas(self.filePaths, self.profile)
        elif self.metodoSeleccionado == "Tarjetas de Red en modo Promiscuo":
            respuesta = volapi.deteccion_red_modo_promiscuo(self.filePaths, self.profile)
        elif self.metodoSeleccionado == "Conexiones Remotas Antiguas":
            respuesta = volapi.obtener_conexiones_remotas_antiguas(self.filePaths, self.profile)
        elif self.metodoSeleccionado == "Urls en procesos de navegadores":
            respuesta = volapi.obtener_url_fuerza_bruta(self.filePaths, self.profile)
        elif self.metodoSeleccionado == "Historial Internet Explorer":
            respuesta = volapi.obtener_historial_iexplorer(self.filePaths, self.profile)
        elif self.metodoSeleccionado == "Recuperar DNS Cache":
            respuesta = volapi.recuperar_dns_cache(self.filePaths)

        # Funciones Exportar
        elif self.metodoSeleccionado == "Todas las Dlls":
            respuesta = volapi.extraer_todas_dlls(self.filePaths, self.directorio_extraer)
        elif self.metodoSeleccionado == "Todos los Drivers":
            respuesta = volapi.extraer_todos_drivers(self.filePaths, self.directorio_extraer)
        elif self.metodoSeleccionado == "Dlls Asociadas a Proceso":
            if self.textparametro.get() == "" or self.textparametro.get() is None:
                respuesta = ["Debe informar el parametro pid para ejecutar el proceso"]
            else:
                respuesta = volapi.extraer_dlls_proceso(self.filePaths,
                                                        self.directorio_extraer, self.textparametro.get())
        elif self.metodoSeleccionado == "Dll Espacio de Memoria":
            if self.textparametro.get() == "" or self.textparametro.get() is None:
                respuesta = ["Debe informar el espacio de memoria en hexadecimal para ejecutar el proceso"]
            else:
                respuesta = volapi.extraer_dlls_memoria(self.filePaths,
                                                        self.directorio_extraer, self.textparametro.get())
        elif self.metodoSeleccionado == "Obtener hash contraseñas":
            respuesta = volapi.obtener_voldado_hash_contrasena(self.filePaths,
                                                    self.directorio_extraer, self.profile)
        if self.ventanaActual == "ventanaProcesosExpertos":
            self.ultimoProcesoEjecutado=self.metodoSeleccionado
            self.textSalida.config(state="normal")
            self.textSalida.delete(1.0, END)
            self.textSalida.update()
            self.textSalida.insert(INSERT, respuesta[0])
            self.textSalida.insert(END, "")
            self.textSalida.config(state="disabled")

            self.textSalidaReducida.config(state="normal")
            self.textSalidaReducida.delete(1.0, END)
            self.textSalidaReducida.update()
            self.textSalidaReducida.insert(INSERT, respuesta[1])
            self.textSalidaReducida.insert(END, "")
            self.textSalida.config(state="disabled")

            self.textSalidaProceso= respuesta[0]
            self.textSalidaReducidaProceso=respuesta[1]
            if respuesta[1] != "Error":
                self.reporteProcesos = self.reporteProcesos + "########### Consulta metodo " + self.metodoSeleccionado \
                                       + time.strftime("%c") + " ###########\n" + respuesta[0]
                self.reporteResumenProcesos = self.reporteResumenProcesos + "########### Consulta metodo " \
                                              + self.metodoSeleccionado \
                                       + time.strftime("%c") + " ###########\n" + respuesta[1]
        elif self.ventanaActual == "ventanaRedExpertos":
            self.ultimoRedEjecutado = self.metodoSeleccionado
            self.textSalida.config(state="normal")
            self.textSalida.delete(1.0, END)
            self.textSalida.update()
            self.textSalida.insert(INSERT, respuesta[0])
            self.textSalida.insert(END, "")
            self.textSalida.config(state="disabled")

            self.textSalidaReducida.config(state="normal")
            self.textSalidaReducida.delete(1.0, END)
            self.textSalidaReducida.update()
            self.textSalidaReducida.insert(INSERT, respuesta[1])
            self.textSalidaReducida.insert(END, "")
            self.textSalida.config(state="disabled")

            self.textSalidaRed = respuesta[0]
            self.textSalidaReducidaRed = respuesta[1]
            if respuesta[1] != "Error":
                self.reporteRed = self.reporteRed + "########### Consulta metodo " + self.metodoSeleccionado \
                                       + time.strftime("%c") + " ###########\n" + respuesta[0]
                self.reporteResumenRed = self.reporteResumenRed + "########### Consulta metodo " +\
                                         self.metodoSeleccionado \
                                       + time.strftime("%c") + " ###########\n" + respuesta[1]
        elif self.ventanaActual == "ventanaMalwareExpertos":
            self.ultimoMalwareEjecutado = self.metodoSeleccionado
            self.textSalida.config(state="normal")
            self.textSalida.delete(1.0, END)
            self.textSalida.update()
            self.textSalida.insert(INSERT, "ventana output malware ejecutado")
            self.textSalida.insert(END, "")
            self.textSalida.config(state="disabled")

            self.textSalidaReducida.config(state="normal")
            self.textSalidaReducida.delete(1.0, END)
            self.textSalidaReducida.update()
            self.textSalidaReducida.insert(INSERT, "ventana output resumen, malware ejecutado")
            self.textSalidaReducida.insert(END, "")
            self.textSalida.config(state="disabled")
            self.textSalidaMalware = "ventana output malware ejecutado"
            self.textSalidaReducidaMalware = "ventana output resumen, malware ejecutado"

        elif self.ventanaActual == "ventanaExtraer":
            self.textSalida.config(state="normal")
            self.textSalida.delete(1.0, END)
            self.textSalida.update()
            self.textSalida.insert(INSERT, respuesta[0])
            self.textSalida.insert(END, "")
            self.textSalida.config(state="disabled")

    def selection_proceso_changed(self, event):
        self.metodoSeleccionado = self.combobox.get()
        self.botonEjecutar.config(state="normal")
        print(self.metodoSeleccionado)
        if self.ventanaActual == "ventanaExtraer":
            self.textparametro.delete(0, END)
            if self.metodoSeleccionado == "Dlls Asociadas a Proceso":
                self.etiqparametros.config(text="PID proceso asociado")
                self.textparametro.config(state="normal")
            elif self.metodoSeleccionado == "Dll Espacio de Memoria":
                self.etiqparametros.config(text="Dirección de Memoria")
                self.textparametro.config(state="normal")
            else:
                self.etiqparametros.config(text="")
                self.textparametro.config(state="disable")

    def selection_ventana_changed(self, event):
        self.irA = self.combobox2.get()
        self.botonIrA.config(state="normal")
        print(self.irA)

    def habilitar_desbotonera_modo_experto(self):
        if self.filePaths is None or self.filePaths == "":
            self.botonAnalisisProcesoE.config(state="disabled")
            self.botonAnalizarRedE.config(state="disabled")
            #self.botonAnalizarMalware.config(state="disabled")
            self.botonGenerarRepore.config(state="disabled")
            self.botonGenerarExtraer.config(state="disabled")

        else:
            self.botonAnalisisProcesoE.config(state="normal")
            self.botonAnalizarRedE.config(state="normal")
            #self.botonAnalizarMalware.config(state="normal")
            self.botonGenerarRepore.config(state="normal")
            self.botonGenerarExtraer.config(state="normal")

    def buscar_directorio_archivo(self):
        self.filePaths = askopenfilename(parent=self.ventanaModoExperto)
        if self.filePaths is not None and self.filePaths != "":
            self.profile = volapi.obtener_perfil(self.filePaths)
            print(self.profile)
            if self.profile != "":
                self.textDireccionArchivo.config(state="normal")
                self.textDireccionArchivo.delete(1.0, END)
                self.textDireccionArchivo.update()
                self.textDireccionArchivo.insert(INSERT, self.filePaths)
                self.textDireccionArchivo.insert(END, "")
                self.textDireccionArchivo.config(state="disabled")

                self.metodoSeleccionado = ""
                self.textSalidaProceso = ""
                self.textSalidaReducidaProceso = ""
                self.textSalidaRed = ""
                self.textSalidaReducidaRed = ""
                self.textSalidaMalware = ""
                self.textSalidaReducidaMalware = ""
                self.ultimoProcesoEjecutado = ""
                self.ultimoRedEjecutado = ""
                self.ultimoMalwareEjecutado = ""
                self.irA = ""
                self.reporteProcesos = ""
                self.reporteResumenProcesos = ""
                self.reporteRed = ""
                self.reporteResumenRed = ""
                self.textoReporte = ""
                self.directorio_extraer = None
                print(self.filePaths)
                self.etiqError.config(text="")
            else:
                print("No contiene profile")
                self.filePaths=""
                self.etiqError.config(text="Error: no se ha encontrado el perfil del archivo", fg="red")


        self.habilitar_desbotonera_modo_experto()

    def validar_respuesta(self):
        respuestaCorrecta = self.listaPreguntas[self.preguntaSeleccionada]["respuestacorrecta"]
        if respuestaCorrecta == self.respuestaSeleccionada:
            self.etiq4.config(text="Correcto", fg="green")
        else:
            self.etiq4.config(text="Incorrecto: La respuesta correcta es la " + respuestaCorrecta, fg="red")

        print(self.preguntaSeleccionada)
        print(len(self.listaPreguntas))
        print(self.listaPreguntas)
        if len(self.listaPreguntas) > self.preguntaSeleccionada + 1:
            self.botonSiguientePregunta.config(state="normal", text="Siguiente Pregunta")
        else:
            if self.ventanaActual == "ventanaProcesos":
                self.botonSiguientePregunta.config(state="normal", text="Analizar RED", bg="#b4a22f")
            elif self.ventanaActual == "ventanaRed":
                self.botonSiguientePregunta.config(state="normal", text="Analizar Malware", bg="#2fb45c")
            elif self.ventanaActual == "ventanaMalware":
                self.botonSiguientePregunta.config(state="normal", text="Resumen", bg='#2f6ab4')

    def obtener_respuesta_seleccionada(self):
        self.respuestaSeleccionada = str(self.valorRespuesta.get())
        self.botonValidarRespuesta.config(state="normal")

    def cambiar_pregunta(self):
        self.preguntaSeleccionada = self.preguntaSeleccionada + 1
        if len(self.listaPreguntas) > self.preguntaSeleccionada:
            self.insertar_pregunta()
            self.botonValidarRespuesta.config(state="disable")
            self.botonSiguientePregunta.config(state="disable")
            self.etiq4.config(text="")
        else:
            print("cambiar a siguiente ventana")
            if self.ventanaActual == "ventanaProcesos":
                self.ventanaProcesos.destroy()
                self.ventana_red()
            elif self.ventanaActual == "ventanaRed":
                self.ventanaRed.destroy()
                self.ventana_malware()
            elif self.ventanaActual == "ventanaMalware":
                self.ventanaMalware.destroy()
                self.ventana_conclusion()

    def onlist_boxclick(self, event):
        seleccionado = self.listbox.get(self.listbox.curselection()[0])
        for ds in self.listaElementos:
            if self.ventanaActual == "ventanaProcesos":
                if ds['proceso'] == seleccionado:
                    print(ds['descripcion'])
                    self.textInfo.config(state="normal")
                    self.textInfo.delete(1.0, END)
                    self.textInfo.update()
                    self.textInfo.insert(INSERT, ds['descripcion'])
                    self.textInfo.insert(END, "")
                    self.textInfo.config(state="disabled")
            elif self.ventanaActual == "ventanaRed":
                if ds['red'] == seleccionado:
                    print(ds['descripcion'])
                    self.textInfo.config(state="normal")
                    self.textInfo.delete(1.0, END)
                    self.textInfo.update()
                    self.textInfo.insert(INSERT, ds['descripcion'])
                    self.textInfo.insert(END, "")
                    self.textInfo.config(state="disabled")
            elif self.ventanaActual == "ventanaMalware":
                if ds['malware'] == seleccionado:
                    print(ds['descripcion'])
                    self.textInfo.config(state="normal")
                    self.textInfo.delete(1.0, END)
                    self.textInfo.update()
                    self.textInfo.insert(INSERT, ds['descripcion'])
                    self.textInfo.insert(END, "")
                    self.textInfo.config(state="disabled")
        print(seleccionado)

    def insertar_pregunta(self):
        try:
            if len(self.listaPreguntas) > self.preguntaSeleccionada:
                self.textPregunta.config(state="normal")
                self.textPregunta.delete(1.0, END)
                self.textPregunta.update()
                self.textPregunta.insert(INSERT, self.listaPreguntas[self.preguntaSeleccionada]["pregunta"])
                self.textPregunta.insert(END, "")
                self.textPregunta.config(state="disabled")
                self.radiobutton1.config(text=self.listaPreguntas[self.preguntaSeleccionada]["opcion1"])
                self.radiobutton2.config(text=self.listaPreguntas[self.preguntaSeleccionada]["opcion2"])
                self.radiobutton3.config(text=self.listaPreguntas[self.preguntaSeleccionada]["opcion3"])
                self.radiobutton4.config(text=self.listaPreguntas[self.preguntaSeleccionada]["opcion4"])
        except:
            self.textPregunta.config(state="normal")
            self.textPregunta.delete(1.0, END)
            self.textPregunta.update()
            self.textPregunta.insert(INSERT, "Error en la consulta")
            self.textPregunta.insert(END, "")
            self.textPregunta.config(state="disabled")
            print("Error en la consulta")

    def recuperar_preguntas(self):
        try:
            rutaBusqueda = ""
            if self.ventanaActual == "ventanaProcesos":
                rutaBusqueda = self.directorioVoLe + "/historias/" + self.historiaSeleccionada +\
                               "/analisisProcesos/preguntas.txt"
                print(rutaBusqueda)
                with open(rutaBusqueda, "r") as archivo:
                    lectura = ""
                    for linea in archivo.readlines():
                        lectura = lectura + linea.strip('\n')
                    print(lectura)
                    if lectura != "":
                        self.listaPreguntas = ast.literal_eval(lectura)
            elif self.ventanaActual == "ventanaRed":
                rutaBusqueda = self.directorioVoLe + "/historias/" + self.historiaSeleccionada +\
                               "/analisisRed/preguntas.txt"
                print(rutaBusqueda)
                with open(rutaBusqueda, "r") as archivo:
                    lectura = ""
                    for linea in archivo.readlines():
                        lectura = lectura + linea.strip('\n')
                    print(lectura)
                    if lectura != "":
                        self.listaPreguntas = ast.literal_eval(lectura)
            elif self.ventanaActual == "ventanaMalware":
                rutaBusqueda = self.directorioVoLe + "/historias/" + self.historiaSeleccionada +\
                               "/analisisMalware/preguntas.txt"
                print(rutaBusqueda)
                with open(rutaBusqueda, "r") as archivo:
                    lectura = ""
                    for linea in archivo.readlines():
                        lectura = lectura + linea.strip('\n')
                    print(lectura)
                    if lectura != "":
                        self.listaPreguntas = ast.literal_eval(lectura)
        except:
            self.textPregunta.config(state="normal")
            self.textPregunta.delete(1.0, END)
            self.textPregunta.update()
            self.textPregunta.insert(INSERT, "Error en la consulta")
            self.textPregunta.insert(END, "")
            self.textPregunta.config(state="disabled")
            print("Error en la consulta")

    def insertar_info_listbox(self):
        try:
            rutaBusqueda = ""
            if self.ventanaActual == "ventanaProcesos":
                rutaBusqueda = self.directorioVoLe + "/historias/" + self.historiaSeleccionada +\
                               "/analisisProcesos/listadoProcesos.txt"
                print(rutaBusqueda)
                with open(rutaBusqueda, "r") as archivo:
                    lectura = ""
                    for linea in archivo.readlines():
                        lectura = lectura + linea.strip('\n')
                    print(lectura)
                    if lectura != "":
                        self.listaElementos = ast.literal_eval(lectura)
                        for ds in self.listaElementos:
                            self.listbox.insert(0, ds["proceso"])
            elif self.ventanaActual == "ventanaRed":
                rutaBusqueda = self.directorioVoLe + "/historias/" + self.historiaSeleccionada +\
                               "/analisisRed/listadoRed.txt"
                print(rutaBusqueda)
                with open(rutaBusqueda, "r") as archivo:
                    lectura = ""
                    for linea in archivo.readlines():
                        lectura = lectura + linea.strip('\n')
                    print(lectura)
                    if lectura != "":
                        self.listaElementos = ast.literal_eval(lectura)
                        for ds in self.listaElementos:
                            self.listbox.insert(0, ds["red"])
            elif self.ventanaActual == "ventanaMalware":
                rutaBusqueda = self.directorioVoLe + "/historias/" + self.historiaSeleccionada +\
                               "/analisisMalware/listadoMalware.txt"
                print(rutaBusqueda)
                with open(rutaBusqueda, "r") as archivo:
                    lectura = ""
                    for linea in archivo.readlines():
                        lectura = lectura + linea.strip('\n')
                    print(lectura)
                    if lectura != "":
                        self.listaElementos = ast.literal_eval(lectura)
                        for ds in self.listaElementos:
                            self.listbox.insert(0, ds["malware"])
        except:
            self.textInfo.config(state="normal")
            self.textInfo.delete(1.0, END)
            self.textInfo.update()
            self.textInfo.insert(INSERT, "Error en la consulta")
            self.textInfo.insert(END, "")
            self.textInfo.config(state="disabled")
            print("Error en la consulta")

    def finalizar_historia(self):
        self.ventanaConclusion.destroy()
        self.initVariables()

    def on_closing(self):
        if self.ventanaActual == "ventanaSeleccionarHistorias":
            self.ventanaSeleccionModoHistoria.destroy()
            self.initVariables()
        elif self.ventanaActual == "ventanaModoExperto":
            self.ventanaModoExperto.destroy()
            self.initVariables()
        elif self.ventanaActual == "ventanaProcesos":
            self.ventanaProcesos.destroy()
            self.initVariables()
        elif self.ventanaActual == "ventanaRed":
            self.ventanaRed.destroy()
            self.initVariables()
        elif self.ventanaActual == "ventanaMalware":
            self.ventanaMalware.destroy()
            self.initVariables()
        elif self.ventanaActual == "ventanaConclusion":
            self.ventanaConclusion.destroy()
            self.initVariables()
        elif self.ventanaActual == "ventanaProcesosExpertos":
            self.ventanaActual = "ventanaModoExperto"
            self.ventanaProcesosExpertos.destroy()
        elif self.ventanaActual == "ventanaRedExpertos":
            self.ventanaActual = "ventanaModoExperto"
            self.ventanaRedExpertos.destroy()
        elif self.ventanaActual == "ventanaMalwareExpertos":
            self.ventanaActual = "ventanaModoExperto"
            self.ventanaMalwareExpertos.destroy()
        elif self.ventanaActual == "ventanaInfo":
            self.ventanaActual = self.ventanaAnterior
            self.ventanaInfo.destroy()
        elif self.ventanaActual == "ventanaReporte":
            self.ventanaActual = "ventanaModoExperto"
            self.ventanaReporte.destroy()
        elif self.ventanaActual == "ventanaExtraer":
            self.ventanaActual = "ventanaModoExperto"
            self.ventanaExtraer.destroy()

    def insertar_conclusiones(self):
        try:
            rutaBusqueda = ""
            rutaBusqueda = self.directorioVoLe + "/historias/" + self.historiaSeleccionada + "/resumen/resumen.txt"
            with open(rutaBusqueda, "r") as archivo:
                lectura = ""
                for linea in archivo.readlines():
                    lectura = lectura + linea.strip('\n')

                if lectura != "":
                    self.textInfo.config(state="normal")
                    self.textInfo.delete(1.0, END)
                    self.textInfo.update()
                    self.textInfo.insert(INSERT, lectura)
                    self.textInfo.insert(END, "")
                    self.textInfo.config(state="disabled")
        except:
            self.textInfo.config(state="normal")
            self.textInfo.delete(1.0, END)
            self.textInfo.update()
            self.textInfo.insert(INSERT, "Error en la consulta")
            self.textInfo.insert(END, "")
            self.textInfo.config(state="disabled")

    def validar_comenzar_historia_seleccionada(self):
        if self.historiaSeleccionada is not None:
            self.ventanaSeleccionModoHistoria.destroy()
            self.ventana_procesos()
        else:
            self.textDescripcionHistoria.config(state="normal")
            self.textDescripcionHistoria.delete(1.0, END)
            self.textDescripcionHistoria.update()
            self.textDescripcionHistoria.insert(INSERT, "Debe seleccionar una Historia para comenzar")
            self.textDescripcionHistoria.insert(END, "")
            self.textDescripcionHistoria.config(state="disabled")

    def selection_changed(self, event):
        self.textDescripcionHistoria.config(state="normal")
        self.textDescripcionHistoria.delete(1.0, END)
        self.textDescripcionHistoria.update()
        self.historiaSeleccionada = self.combobox.get()
        if self.historiaSeleccionada is not None: self.obtener_descripcion_historia()

    def obtener_descripcion_historia(self):
        try:
            rutaHistorias = self.directorioVoLe + "/historias/" + self.historiaSeleccionada + "/descripcion.txt"
            print(rutaHistorias)
            with open(rutaHistorias, "r") as archivo:
                self.textDescripcionHistoria.config(state="normal")
                for linea in archivo.readlines():
                    self.textDescripcionHistoria.insert(INSERT, linea)
                self.textDescripcionHistoria.insert(END, "")
                self.textDescripcionHistoria.config(state="disabled")
        except:
            self.textDescripcionHistoria.config(state="normal")
            self.textDescripcionHistoria.insert(INSERT, "ERROR en la lectura de la descripcion de la historia")
            self.textDescripcionHistoria.insert(END, "")
            self.textDescripcionHistoria.config(state="disabled")

    def obtener_historias(self):
        try:
            rutaHistorias = self.directorioVoLe + "/historias/listahistorias.txt"
            with open(rutaHistorias, "r") as archivo:
                for linea in archivo.readlines():
                    self.historias.append(linea.rstrip('\n'))
        except:
            self.historias = []

def main():
    vole().mainloop()

if __name__ == '__main__':
    main()