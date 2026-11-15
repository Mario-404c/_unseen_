import time, sys, json, os, stun, socket, tempfile, subprocess, getpass, questionary
import gnupg
from questionary import Choice
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
import asyncio
from modules import network, gossip, utils

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
session = PromptSession()

KEYS_DIR = os.path.join(BASE_DIR, "modules", "keys")
os.makedirs(KEYS_DIR, mode=0o700, exist_ok=True)
gpg = gnupg.GPG(gnupghome=KEYS_DIR)

subprocess.run(["gpgconf", "--homedir", os.path.join(BASE_DIR,"modules", "keys"), "--kill", "gpg-agent"])
config_path = os.path.join(BASE_DIR, "config.json")

peers = []
with open(os.path.join(BASE_DIR, "tempkeys.json"), "r") as f:
    tempkeys = json.load(f)
    for k in tempkeys:
        priv = gpg.delete_keys(k["fingerprint"], secret=True, expect_passphrase=False)
        pub = gpg.delete_keys(k["fingerprint"])
with open(os.path.join(BASE_DIR, "tempkeys.json"), "w") as f:
    json.dump([], f)

async def main():
    utils.stampa_logo()
    File_esiste = False
    Alg = "pgp"
    if os.path.exists(config_path) and os.path.getsize(config_path) > 0:
        File_esiste = True
        Nome, porta, fingerprint, utils.verbose, utils.avvio_tempuser, utils.colori = utils.leggi(config_path)
    
    ip_privato = None 
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_privato, _ = s.getsockname()
    except Exception as e:
        print(f"Impossibile determinare l'ip locale: {e}")
    
    tipo_nat, ip_pubblico, porta_pubblica = stun.get_ip_info(
        stun_host="stun.l.google.com", stun_port=19302
    )
    richieste_in_attesa = []

    if utils.avvio_tempuser == False:
        scelta = await questionary.select(
        "Login",
        choices=[
            *([Choice("Login con utente precedente", value=1)] if File_esiste else []),
            Choice("Crea nuovo utente permanente", value=2),
            Choice("Utente temporaneo", value=3),
            ],
        ).ask_async()
    elif utils.avvio_tempuser == True:
        scelta = 3

    # Tempuser
    if scelta == 3:
        Nome, porta, password = utils.crea_tempuser()
        input_data = gpg.gen_key_input(
            name_real= Nome,
            name_email='Talk@secure.com',
            passphrase=password,
            key_type='RSA',
            key_length=2048,
            )
        key = gpg.gen_key(input_data)
        if not key.fingerprint:
            print("Generazione della chiave fallita")
            sys.exit(1)
        fingerprint = key.fingerprint
        chiave_pubblica = gpg.export_keys(key.fingerprint)
        me = {
            "fingerprint": fingerprint,
            "timestamp": time.time()
            }
        tempkeys.append(me)
        with open(os.path.join(BASE_DIR, "tempkeys.json"), "w") as f:
            json.dump(tempkeys, f, indent=2)
    
    # Login
    if scelta == 1 and File_esiste == True:
        passw = False
        t = 3
        while passw == False:
            utils.cprint(f"Inserisci password per l'utente: {Nome}", "Login")
            password = getpass.getpass()
            result = gpg.sign(
                "test",
                keyid=fingerprint,
                passphrase=password,
                extra_args=['--pinentry-mode', 'loopback']
            )
            if result.status != 'signature created' or not result.data:
                if t == 0:
                    utils.cprint("Tentativi esauriti, chiusura del programma... ", "Err")
                    sys.exit()
                print(f"Password sbagliata, ti restano \033[31m {t} \033[0m tentativi.")
                t = t - 1
            else:
                utils.cprint("Password corretta", "Success")
                chiave_pubblica = gpg.export_keys(fingerprint)
                passw = True       

    # Nuovo utente
    if scelta == 2:
        Nome_disponibile = False
        retry = False
        while Nome_disponibile == False:
            Nome = utils.seleziona_nome(retry)
            esito = utils.ceck_nome(Nome)
            if esito == "OK":
                utils.cprint("Nome disponibile!", "Success")
                Nome_disponibile = True
            elif esito.split(",", 3)[0] == "exists":
                utils.cprint("Nome non disponibile, inseriscine un'altro", "Info")
                retry = True
        
        porta = utils.seleziona_porta()
        
        os.system("cls" if os.name == "nt" else "clear")
        while True:
            password = getpass.getpass("\033[34m Scegli una password per la crittografia (Obbligatorio): \033[0m")
            controllo = getpass.getpass("\033[34m Reinserisci la password: \033[0m")
            if password == controllo:
                break
            else:
                os.system("cls" if os.name == "nt" else "clear")
                utils.cprint("Le due password inserite sono diverse!", "Err")

        utils.vprint("Sto generando la coppia di chiavi...")
        input_data = gpg.gen_key_input(
            name_real= Nome,
            name_email='Talk@secure.com',
            passphrase=password,
            key_type='RSA',
            key_length=4096,
            )
        key = gpg.gen_key(input_data)
        if not key.fingerprint:
            utils.cprint("Generazione delle chiavi fallita", "Err")
            sys.exit(1)
        fingerprint = key.fingerprint
        chiave_pubblica = gpg.export_keys(key.fingerprint)
        print("\033[96m Fingerprint della tua nuova chiave: \033[0m \n", fingerprint)
        ris = utils.y_n("Vuoi visualizzare la tua nuova chiave pubblica? (y/n)")
        if ris == "y":
            print(chiave_pubblica)
        
        esito = utils.memorizza_altervista(Nome, ip_pubblico, porta_pubblica, fingerprint)
        if esito == "done":
            utils.vprint("Hai correttamente memorizzato i tuoi dati sul server, sei autenticato!") 
        else:
            utils.cprint("C'è stato un errore nell'autenticazione al server!", "Err")
                
        utils.memorizza(Nome, porta, fingerprint, True, False, utils.colori, False, config_path)
        input("\033[32m Login effettuato! Premi invio per continuare... \033[0m ")

    # Fine login
    
    task_server = asyncio.create_task(gossip.ascolto(porta, peers, richieste_in_attesa, chiave_pubblica, gpg, fingerprint, password, session, BASE_DIR))
    asyncio.create_task(gossip.ascolta_richieste_webrtc (ip_pubblico, porta_pubblica, Nome, peers, richieste_in_attesa, chiave_pubblica, gpg, fingerprint, password, session, BASE_DIR))
    
    A = True
    while A:
        os.system("cls" if os.name == "nt" else "clear")
        utils.stampa_logo()
        utils.print_information(Nome, ip_pubblico, porta_pubblica, tipo_nat, ip_privato, porta)
        scelta = await questionary.select(
        "Menù chat",
        choices=[
            Choice("Contatta un peer", value=1),
            Choice("Attendi che qualcuno ti contatti", value=2),
            Choice("Visualizza i peer con cui hai gia parlato", value=3),
            Choice("Impostazioni", value=4),
            Choice("Esci", value=5)
            ],
        ).ask_async()
        
        if scelta == 1:
            os.system("cls" if os.name == "nt" else "clear")
            utils.print_information(Nome, ip_pubblico, porta_pubblica, tipo_nat, ip_privato, porta)
            
            ricerca = await asyncio.to_thread(input, "Inserisci l'username o l'ip:porta del destinatario: ")
            procedi, bypass_auth_username = False, False
            username_target, ip_destinazione, porta_destinazione, fingerprint_destinatario = utils.known_hosts("exists?", ricerca, None, None, None, None, BASE_DIR)
            
            if username_target != None:
                utils.vprint("Host già registrato localmente, skippo la verifica lato server... ")
                procedi = True
            else:
                utils.vprint("Host sconosciuto, cerco sul server... ")
                ip_destinazione, porta_destinazione, username_target, fingerprint_destinatario = None, None, None, None
                if ":" in ricerca:
                    ip_destinazione, porta_destinazione = ricerca.split(":", 1)
                    utils.vprint(f"Cerco una corrispondenza per gli indirizzo e porta: {ricerca}")
                    response = utils.ceck_indirizzo(ip_destinazione, porta_destinazione)
                    if response == "OK":
                        ris = utils.y_n("L'indirizzo cercato non risulta essere salvato sul server, questo significa che non è possibile verificare il fingerprint server-side, tento lo stesso di contattarlo? (y/n)")
                        if ris == "y":
                            procedi = True
                            bypass_auth_username = True
                    elif response.split(",", 2)[0] == "exists":
                        trash, username_target, fingerprint_destinatario = response.split(",", 3)
                        procedi = True
                else:
                    username_target = ricerca
                    utils.vprint(f"Cerco una corrispondenza per l'username: {username_target}")
                    response = utils.ceck_nome(username_target)
                    if response == "OK":
                        ris = utils.y_n("Il nome non risulta essere salvato sul server, provo lo stesso a fare il signaling con webRTC?")
                        if ris == "y":
                            procedi = True
                            bypass_auth_username = True
                    elif response.split(",", 3)[0] == "exists":
                        trash, ip_destinazione, porta_destinazione, fingerprint_destinatario = response.split(",", 3)
                        procedi = True
            
            if procedi == True:
                if ip_destinazione != None:
                    utils.vprint(f"Corrispondenza trovata per l'username '{username_target}': ")
                    utils.vprint(f"Ip:porta associati: {ip_destinazione}:{porta_destinazione}")
                    utils.vprint(f"Fingerprint associato: {fingerprint_destinatario}")
                
                try:
                    utils.vprint("Provo ad aprire una connessione diretta...")
                    await network.tenta_connessione_diretta(ip_destinazione, porta_destinazione, Nome, Alg, chiave_pubblica, fingerprint, gpg, password, session, username_target, fingerprint_destinatario, bypass_auth_username, BASE_DIR)
                        
                except(ConnectionRefusedError, ConnectionResetError, asyncio.TimeoutError, OSError, ValueError):
                    utils.vprint("Peer irraggiungibile per via diretta, tento con webRTC...")
                    if username_target != None:
                        ricerca = username_target
                    else:
                        ricerca = ip_destinazione + ":" + str(porta_destinazione)
                    try:
                        await network.tenta_connessione_webRTC(ip_pubblico, porta_pubblica, Nome, ricerca, peers, richieste_in_attesa, chiave_pubblica, gpg, fingerprint, password, session, Alg, username_target, fingerprint_destinatario, bypass_auth_username, BASE_DIR)
                    except Exception as e:
                        utils.cprint(f"E' stato impossibile stabilire una connessione (WebRTC): {e!r}", "Err")
                except Exception as e:
                    utils.cprint(f"E' stato impossibile stabilire una connessione: {e}", "Err")

        frase = f"In ascolto sulla porta {porta} "
        if scelta == 2:
            utils.print_information(Nome, ip_pubblico, porta_pubblica, tipo_nat, ip_privato, porta)
            Contatto = False
            while(Contatto == False):
                if richieste_in_attesa:
                    os.system("cls" if os.name == "nt" else "clear")
                    richiesta_dal_menu = richieste_in_attesa[0]
                    testo = (
                        "Richiesta di connessione diretta da parte di: "
                        + str(richiesta_dal_menu["indirizzo_client"])
                        + " con nome: " + str(richiesta_dal_menu["nome"])
                        + " tramite " + str(richiesta_dal_menu["tipo"])
                    )
                    utils.cprint(testo, "Info")
                    B = True
                    while B:
                        risposta = (await asyncio.to_thread(
                            input, "Accettare? | y/n\n"
                        )).strip()
                        if(risposta.lower() == "y" or risposta.lower() == "s"):
                            richiesta_dal_menu["decisione"] = "ACCETTATA"
                            A = False
                            B = False
                            Contatto = True
                            
                        elif(risposta.lower() == "n"):
                            richiesta_dal_menu["decisione"] = "RIFIUTATA"
                            B = False
                            input(f"\033[31m Connessione rifiutata, attendo input... \033[0m")
                            richieste_in_attesa.pop(0)
                            os.system("cls" if os.name == "nt" else "clear")
                        else:
                            os.system("cls" if os.name == "nt" else "clear")
                            print("Non hai selezionato nessuna delle opzioni possibili!")
                else:
                    os.system("cls" if os.name == "nt" else "clear")
                    utils.print_information(Nome, ip_pubblico, porta_pubblica, tipo_nat, ip_privato, porta)
                    frase = frase + "."
                    print(frase)
                    await asyncio.sleep(2)
                    
        if scelta == 3:
            with open(os.path.join(BASE_DIR, "known_hosts.json"), "r") as f:
                known_hosts = json.load(f)
            if known_hosts != []:
                for h in known_hosts:
                    print(h["nome"], " - ", h["fingerprint"])
            else:
                utils.cprint("Non hai parlato ancora con nessun peer!", "Warning")
                
        if scelta == 4:
            os.system("cls" if os.name == "nt" else "clear")
            await utils.change_configs(config_path, BASE_DIR)
            
        if scelta == 5:
            A = False

    await task_server

asyncio.run(main())