import shutil, subprocess, sys
import time, os, requests, json, secrets, random, questionary
from questionary import Choice

verbose = False
avvio_tempuser = False

COLORI = {
    "rosso": "\033[31m",
    "verde": "\033[32m",
    "giallo": "\033[33m",
    "blu": "\033[34m",
    "magenta": "\033[35m",
    "ciano": "\033[36m",
    "bianco": "\033[37m",
}
RESET = "\033[0m"

COLORI_DEFAULT = {
    "NM": "\033[37m",
    "ND": "\033[37m",
    "TM": "\033[37m",
    "TD": "\033[37m",
    "Err": "\033[31m",
    "Warning": "\033[33m \033[1m",
    "Info": "\033[35m",
    "Verbose": "\033[37m",
    "Success": "\033[32m",
    "Login": "\033[34m"
}

colori = COLORI_DEFAULT

def stampa_logo():
    art=r"""
    +=====================================+
    |   _   _ _ __  ___  ___  ___ _ __    |
    |  | | | | '_ \/ __|/ _ \/ _ \ '_ \   |
    |  | |_| | | | \__ \  __/  __/ | | |  |
    |   \__,_|_| |_|___/\___|\___|_| |_|  |
    +=====================================+
    """
    print("\033[34m", art, "\033[0m")

def print_information(Nome, ip_pubblico, porta_pubblica, tipo_nat, ip_privato, porta):
    print("Sei loggato come '", Nome, "'")        
    print("Indirizzo pubblico: \033[1m", ip_pubblico,  ":", porta_pubblica, "\033[0m , NAT type (approssimativo): \033[1m", tipo_nat, "\033[0m")
    print("Indirizzo privato: \033[1m", ip_privato, ":", porta, "\033[0m")
    print("L'algoritmo di crittografia utilizzato da questa versione è: \033[1m pgp \033[0m")

def seleziona_ip():
    A = True
    while A == True:
        indirizzo = input("Inserisci l'ip interno alla rete su cui ascoltare (x.x.x.x): ")
        risposta = input("Questi dati sono corretti? (y/n)")
        if risposta.lower() == "y" or risposta.lower() == "s":
            A = False
        elif risposta.lower() == "n":
            A = True
        else:
            print("Non hai selezionato nessuna delle opzioni possibili! (y/n)")
    return indirizzo

def seleziona_porta():
    A = True
    while A == True:
        indirizzo = input("Seleziona una porta locale da usare: ")
        if indirizzo.isdigit() and 1024 < int(indirizzo) < 65536:
            risposta = input("Questa porta è corretta? (y/n)")
            if risposta.lower() == "y" or risposta.lower() == "s":
                A = False
            elif risposta.lower() == "n":
                A = True
            else:
                print("Non hai selezionato nessuna delle opzioni possibili! (y/n)")
        else:
            print("La porta deve essere un numero tra 1025 e 65535")
    return indirizzo

def seleziona_nome(Retry):
    B = True
    if Retry == True:
        Nome = input("Reinserire: ")
    else:
        while B:
            Nome = input("Inserisci il tuo \033[1m nome \033[0m: (questo nome sara' prmanentemente associato alla tua chiave pubblica)")
            risposta = input(f"Questo \033[1m nome \033[0m e' corretto?: \033[1m {Nome} \033[0m (y/n)")
            if risposta.lower() == "y" or risposta.lower() == "s":
                B = False
            elif risposta.lower() == "n":
                print("Reinserisci il nome")
            else:
                print("Non hai selezionato nessuna delle opzioni possibili! (y/n)")
            
    return Nome

def memorizza(nome, porta, fingerprint, verbose, avvio_tempuser, colors, File_esiste, config_path):

    if File_esiste == True:
        nome_M, porta_M, fingerprint_M, verbose_M, avvio_tempuser_M, colors_M = leggi(config_path)
    
    if nome == "-":
        nome = nome_M
    if porta == "-":
        porta = porta_M
    if fingerprint == "-":
        fingerprint = fingerprint_M
    if verbose == "-":
        verbose = verbose_M
    if avvio_tempuser == "-":
        avvio_tempuser = avvio_tempuser_M
    if colors == "-":
        colors = colors_M
        
    config = {
        "nome": nome,
        "porta": porta,
        "fingerprint": fingerprint,
        "verbose": verbose,
        "avvio_tempuser": avvio_tempuser,
        "colors": colors,
        "timestamp": time.time(),
    }
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
        
    print("I dati sono stati salvati. ")


def leggi(config_path):
    
    with open(config_path, encoding="utf-8") as f:
        config = json.load(f)
        
        nome = config["nome"]
        porta = config["porta"]
        fingerprint = config["fingerprint"]
        verbose = config["verbose"]
        avvio_tempuser = config["avvio_tempuser"]
        colors = config["colors"]

    return nome, porta, fingerprint, verbose, avvio_tempuser, colors

def ceck_nome(Nome):
    payload = {
        "user": Nome,
        "ip": "",
        "porta": "",
        "fingerprint": "",
        "tipo": "ceck"
        }
        
    response = requests.get(url = "http://mario404c.altervista.org/Secchat/ceck_username.php", params = payload)
    return response.text # OK / exists,ip,porta,fingerprint

def ceck_indirizzo(ip, porta):
    payload = {
        "user": "",
        "ip": ip,
        "porta": porta,
        "fingerprint": "",
        "tipo": "ceck_addr"
        }
        
    response = requests.get(url = "http://mario404c.altervista.org/Secchat/ceck_username.php", params = payload)

    return response.text # OK / exists,username,fingerprint

def memorizza_altervista(Nome, indirizzo, porta, fingerprint):
    payload = {
        "user": Nome,
        "ip": indirizzo,
        "porta": porta,
        "fingerprint": fingerprint,
        "tipo": "send"
        }
        
    response = requests.get(url = "http://mario404c.altervista.org/Secchat/ceck_username.php", params = payload)
    return response.text

def y_n(domanda):
    esci = False
    while esci == False:
        print(domanda)
        risposta = input()
        if risposta.lower() == "y" or risposta.lower() == "n":
            esci = True
        else:
            os.system("cls" if os.name == "nt" else "clear")
            print("Non hai inserito una risposta valida!")
    return risposta.lower()

def known_hosts(richiesta, ricerca, new_username, new_ip, new_port, new_fingerprint, base_dir):
    path = os.path.join(base_dir, "known_hosts.json")
    with open(path, "r", encoding="utf-8") as f:
        dati = json.load(f)
    
    if richiesta == "exists?":
        if ":" in ricerca:
            ip, porta = ricerca.split(":", 1)
            for h in dati:
                if ip == h["ip"] and str(porta) == str(h["porta"]):
                    username = h["nome"]
                    fingerprint = h["fingerprint"]
                    return username, ip, porta, fingerprint
        else:
            username = ricerca
            for h in dati:
                if username == h["nome"]:
                    ip = h["ip"]
                    porta = h["porta"]
                    fingerprint = h["fingerprint"]
                    return username, ip, porta, fingerprint

                
        return None, None, None, None
                
    elif richiesta == "load":
        load = {
            "nome":new_username,
            "ip":new_ip,
            "porta":new_port,
            "fingerprint":new_fingerprint
        }
        dati.append(load)
        
        with open(path, "w", encoding="utf-8") as f:
            json.dump(dati, f, indent=2, ensure_ascii=False)
        return "OK"
    
def crea_tempuser():
    nome = f"User-{secrets.token_hex(4)}"
    porta_locale = random.randint(1025, 49151)
    password = secrets.token_hex(16)
    
    return nome, porta_locale, password

async def change_configs(config_path, base_dir):
    global colori, verbose, avvio_tempuser
    nome = porta = fingerprint = verbose_n = avvio_tempuser_n = colori_n = "-"
    
    while True:
        scelta = await questionary.select(
        "Impostazioni",
        choices=[
            Choice("Modalità verbose", value=1),
            Choice("Cambia porta locale", value=2),
            Choice("Personalizzazione", value=3),
            Choice("Utente temporaneo", value=4),
            Choice("Reimposta a valori default", value=5),
            Choice([("fg:ansired bold", "Distruggi dati")], value=6),
            Choice("Torna al menù chat", value=7),
            ],
        ).ask_async()
        
        if scelta == 1:
            if verbose == True:
                print("\033[1;33m True \033[0m")
            else:
                print("\033[1;33m False \033[0m")
                
            s = await questionary.select( "Modalità verbose: ",
                choices=[
                    Choice("True", value=1),
                    Choice("False", value=2),
                ], ).ask_async()
            if s == 1:
                verbose_n = True
                verbose = True
            elif s == 2:
                verbose_n = False
                verbose = False

        elif scelta == 2:
            porta = seleziona_porta()
            
        elif scelta == 3:
            tipo_messaggio = await questionary.select("Personalizza colori di: ",
                choices=[
                    Choice("Nome mittente", value = "NM"),
                    Choice("Nome destinatario", value = "ND"),
                    Choice("Testo mittente", value = "TM"),
                    Choice("Testo destinatario", value = "TD"),
                    Choice("Messaggi di errore", value = "Err"),
                    Choice("Avvisi (warning)", value = "Warning"),
                    Choice("Messaggi informativi", value = "Info"),
                    Choice("Messaggi verbose", value = "Verbose"),
                    Choice("Messaggi di operazione riuscita", value = "Success"),
                    Choice("Messaggi di login/inserimento password", value = "Login"),
                ], ).ask_async()
            
            colore = await questionary.select("Scegli il colore: ",
                choices=[
                    Choice([("fg:ansired", "Rosso")], value="\033[31m"),
                    Choice([("fg:ansigreen", "Verde")], value="\033[32m"),
                    Choice([("fg:ansiyellow", "Giallo")], value="\033[33m"),
                    Choice([("fg:ansiblue", "Blu")], value="\033[34m"),
                    Choice([("fg:ansimagenta", "Magenta")], value="\033[35m"),
                    Choice([("fg:ansicyan", "Ciano")], value="\033[36m"),
                    Choice([("fg:ansiwhite", "Bianco")], value="\033[37m"),
                    
                    Choice([("fg:ansired bold", "Rosso grassetto")], value="\033[31m \033[1m"),
                    Choice([("fg:ansigreen bold", "Verde grassetto")], value="\033[32m \033[1m"),
                    Choice([("fg:ansiyellow bold", "Giallo grassetto")], value="\033[33m \033[1m"),
                    Choice([("fg:ansiblue bold", "Blu grassetto")], value="\033[34m \033[1m"),
                    Choice([("fg:ansimagenta bold", "Magenta grassetto")], value="\033[35m \033[1m"),
                    Choice([("fg:ansicyan bold", "Ciano grassetto")], value="\033[36m \033[1m"),
                    Choice([("fg:ansiwhite bold", "Bianco grassetto")], value="\033[37m \033[1m"),
                ], ).ask_async()
            
            colori_n = colori
            colori_n[tipo_messaggio] = colore
            colori = colori_n
            
        elif scelta == 4:
            if avvio_tempuser == True:
                print("\033[1;33m True \033[0m")
            else:
                print("\033[1;33m False \033[0m")
                
            s = await questionary.select( "Avvio senza conferma (Il programma si avvierà automaticamente con l'utente temporaneo): ",
                choices=[
                    Choice("True", value=1),
                    Choice("False", value=2),
                ], ).ask_async()
            if s == 1:
                avvio_tempuser_n = True
                avvio_tempuser = True
            elif s == 2:
                avvio_tempuser_n = False
                avvio_tempuser = False
                
        elif scelta == 5:
            s = await questionary.select("Vuoi ripristinare tutte le impostazioni?",
                choices=[ Choice("Si", value=1), Choice("No", value=2),], ).ask_async()
            if s == "Si":
                verbose_n = False
                avvio_tempuser_n = False
                colori_n = COLORI_DEFAULT
                
        elif scelta == 6:
            r = y_n("\033[31m \033[1m Sei sicuro di voler cancellare tutti i dati? (Chiavi/Known hosts/Config) \033[0m")
            if r == "y":
                keys_dir = os.path.join(base_dir, "modules", "keys")
                subprocess.run(["gpgconf", "--homedir", keys_dir, "--kill", "gpg-agent"],
                            capture_output=True)
                shutil.rmtree(keys_dir, ignore_errors=True)

                if os.path.isdir(keys_dir) and os.listdir(keys_dir):
                    cprint("Impossibile cancellare le chiavi (file in uso?). Nessun dato eliminato.", "Err")
                    continue

                os.makedirs(keys_dir, exist_ok=True)

                open(config_path, "w").close()
                for nome_file in ("known_hosts.json", "tempkeys.json"):
                    with open(os.path.join(base_dir, nome_file), "w", encoding="utf-8") as f:
                        json.dump([], f)

                sys.stdout.flush()
                os._exit(0)
                    
        elif scelta == 7:
            break
        
        memorizza(nome, porta, fingerprint, verbose_n, avvio_tempuser_n, colori_n, True, config_path)
        
def vprint(*args, **kwargs):
    if verbose == True:
        print(colori["Verbose"], *args, RESET, **kwargs)

def cprint(testo, tipo, **kwargs):
    print(colori[tipo], testo, RESET, **kwargs)