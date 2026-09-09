import time, os

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

def seleziona_nome():
    B = True
    NomeServ = "Server"
    while B:
        risposta = input("Vuoi scegliere un \033[1m nome \033[0m ? (y/n): ")
        if risposta.lower() == "y" or risposta.lower() == "s":
            NomeServ = input("Inserisci il \033[1m nome \033[0m: ")
            B = False
        elif risposta.lower() == "n":
            B = False
        else:
            print("Non hai selezionato nessuna delle opzioni possibili! (y/n)")
            
    return NomeServ

def seleziona_alg():
    C = True
    while C:
        risposta = input("Scegli la crittografia |\033[34m Cesare, Xor, pgp \033[0m|: ")
        if risposta.lower() == "cesare":
            Alg = "cesare"
            C = False
        elif risposta.lower() == "xor":
            Alg = "xor"
            C = False
        elif risposta.lower() == "pgp":
            Alg = "pgp"
            C = False
        else:
            print("Non hai selezionato nessuna delle opzioni possibili! |\033[34m Cesare, Xor, pgp \033[0m|")
    return Alg

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
     