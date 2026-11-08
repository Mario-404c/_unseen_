import time, os, requests, json, secrets, random

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

def print_information(Nome, ip_pubblico, porta_pubblica, tipo_nat, ip_privato, porta, Alg):
    print("Sei loggato come '", Nome, "'")        
    print("Indirizzo pubblico: \033[1m", ip_pubblico,  ":", porta_pubblica, "\033[0m , NAT type (approssimativo): \033[1m", tipo_nat, "\033[0m")
    print("Indirizzo privato: \033[1m", ip_privato, ":", porta, "\033[0m")
    print("L'algoritmo di crittografia selezionato è: \033[1m", Alg, "\033[0m")

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
        risposta = input("Questi dati sono corretti? (y/n)")
        if risposta.lower() == "y" or risposta.lower() == "s":
            A = False
        elif risposta.lower() == "n":
            A = True
        else:
            print("Non hai selezionato nessuna delle opzioni possibili! (y/n)")
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

def memorizza(Nome, porta, Alg, fingerprint, File_esiste, base_dir):
    if File_esiste == True:
        risposta = input("Vuoi memorizzare questi dati e \033[1m sovrascrivere \033[0m i precedenti? ")
    else:
        risposta = "y"
    Esci = False
    while Esci == False:
        if risposta.lower() == "y" or risposta.lower() == "s":
            with open(os.path.join(base_dir, "config.txt"), "w") as f:
                f.write(f"{Nome}\n")
                f.write(f"{porta}\n")
                f.write(f"{Alg}\n")
                f.write(f"{time.time()}\n")
                f.write(f"{fingerprint}")
            Esci = True
        elif risposta.lower() == "n":
            print("I dati non sono stati sovrascritti. ")
            Esci = True
        else:
            print("Non hai inserito nessuna delle opzioni possibili!")

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
    alg = "pgp"
    password = secrets.token_hex(16)
    
    return nome, porta_locale, alg, password