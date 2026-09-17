import time, sys, json, os, stun, socket, tempfile,subprocess,getpass
import gnupg
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
import asyncio
from modules import encryption, network, selection, gossip

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
session = PromptSession()
alfabeto = "<|b'0#c)d_e$@&61fg!=£hi*j5:klmçùn]2?op^qrs(tuàv,wx+yz7 A+BC.8DèEF;3GHIJaLM[NOòPQéR4>STU-èV*WìX9YZ"
gpg = gnupg.GPG(gnupghome=os.path.join(BASE_DIR,"modules", "keys"))
subprocess.run(["gpgconf", "--homedir", os.path.join(BASE_DIR,"modules", "keys"), "--kill", "gpg-agent"])
config_path = os.path.join(BASE_DIR, "config.txt")

peers = []

async def main():
    selection.stampa_logo()
    fingerprint = None
    File_esiste = False

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_privato, porta = s.getsockname()
    except Exception as e:
        print(f"Impossibile determinare l'ip locale: {e}")
    
    tipo_nat, ip_pubblico, porta_pubblica = stun.get_ip_info(
        stun_host="stun.l.google.com", stun_port=19302
    )
    
    dati_precedenti_selezione = "n"
    richieste_in_attesa = []

    if os.path.exists(config_path) and os.path.getsize(config_path) > 0:
        File_esiste = True
        dati_precedenti_selezione = input("\033[33m Vuoi usare i dati precedenti? (y/n) \033[0m").strip()
        if dati_precedenti_selezione.lower() == "y" or dati_precedenti_selezione.lower() == "s":
            with open(config_path, "r") as f:
                righe = f.readlines()   
                righe = [riga.strip() for riga in righe]

                Nome = righe[0]
                porta = int(righe[1])
                Alg = righe[2]
                ultimo_gossip = righe[3]
                fingerprint = righe[4]
                chiave = 0
                
            passw = False
            t = 3
            while passw == False:
                print("Inserisci password per l'utente: ", Nome)
                password = getpass.getpass()
                result = gpg.sign(
                    "test",
                    keyid=fingerprint,
                    passphrase=password,
                    extra_args=['--pinentry-mode', 'loopback']
                )
                if result.status != 'signature created' or not result.data:
                    if t == 0:
                        print("Tentativi esauriti, chiusura del programma... ")
                        sys.exit()
                    print(f"Password sbagliata, ti restano \033[31m {t} \033[0m tentativi.")
                    t = t - 1
                else:
                    print("Password corretta")
                    chiave_pubblica = gpg.export_keys(fingerprint)
                    passw = True       

    if dati_precedenti_selezione.lower() == "n" or File_esiste == False:
        Nome_disponibile = False
        retry = False
        while Nome_disponibile == False:
            Nome = selection.seleziona_nome(retry)
            esito = selection.ceck_nome(Nome)
            if esito == "OK":
                print("Nome disponibile!")
                Nome_disponibile = True
            elif esito.split(",", 3)[0] == "exists":
                print("Nome non disponibile, inseriscine un'altro")
                retry = True
            
        Alg = selection.seleziona_alg()
        
        porta = selection.seleziona_porta()
        
        password = getpass.getpass("Scegli una password per la crittografia (Obbligatorio): ")
        
        if Alg.lower() == "cesare" or Alg.lower() == "xor":
                chiave = encryption.crea_chiave(password)
                print("La tua chiave di crittografia è: \033[93;40m", chiave, "\033[0m")
                print("Sto generando la coppia di chiavi... ")
                input_data = gpg.gen_key_input(
                    name_real= Nome,
                    name_email='Talk@secure.com',
                    passphrase=password,
                    key_type='RSA',
                    key_length=4096,
                    )
                key = gpg.gen_key(input_data)
                fingerprint = key.fingerprint
                chiave_pubblica = gpg.export_keys(key.fingerprint)
                print("Fingerprint della tua nuova chiave: \n", fingerprint)
                ris = await asyncio.to_thread(
                    input, "Vuoi visualizzare la tua chiave pubblica? | y/n \n"
                )
                if ris.lower() == "y":
                    print(chiave_pubblica)
                
        elif Alg.lower() == "pgp" and fingerprint == None:
                print("Sto generando la coppia di chiavi... ")
                input_data = gpg.gen_key_input(
                    name_real= Nome,
                    name_email='Talk@secure.com',
                    passphrase=password,
                    key_type='RSA',
                    key_length=4096,
                    )
                key = gpg.gen_key(input_data)
                fingerprint = key.fingerprint
                chiave_pubblica = gpg.export_keys(key.fingerprint)
                print("Fingerprint della tua nuova chiave: \n", fingerprint)
                ris = await asyncio.to_thread(
                    input, "Vuoi visualizzare la tua chiave pubblica? | y/n \n"
                )
                if ris.lower() == "y":
                    print(chiave_pubblica)
                chiave = 0
        
        esito = selection.memorizza_altervista(Nome, ip_pubblico, porta_pubblica, fingerprint)
        if esito == "done":
            print("Hai correttamente memorizzato i tuoi dati sul server, sei autenticato") 
        else:
            print("C'è stato un errore nell'autenticazione al server")
                   
        selection.memorizza(Nome, porta, Alg, fingerprint, File_esiste, BASE_DIR)
        input("Login effettuato, premi invio per continuare... ")

    # Fine login
    os.system("cls" if os.name == "nt" else "clear")
    selection.stampa_logo()
    selection.print_information(Nome, ip_pubblico, porta_pubblica, tipo_nat, ip_privato, porta, Alg)
    
#    with open(os.path.join(BASE_DIR, "ip_list.json"), "r") as f:
#            peers = json.load(f)
    
#    io_mancante = True
#    for p in peers:
#        if p["ip"] == ip_pubblico and p["porta"] == porta_pubblica:
#            io_mancante = False
#    if io_mancante == True:
#       me = {
#       "ip": ip_pubblico,
#       "nome": Nome,
#       "porta": porta_pubblica,
#       "timestamp": time.time(),
#       "stato": "online"
#       }
#       peers.append(me)

    # asyncio.create_task(gossip.gossip(peers, ip_pubblico, BASE_DIR))
    # asyncio.create_task(gossip.ceck_unreachable(peers, BASE_DIR))
    task_server = asyncio.create_task(gossip.ascolto(porta, peers, richieste_in_attesa, chiave, chiave_pubblica, gpg, fingerprint, password, alfabeto, session, BASE_DIR))
    asyncio.create_task(gossip.ascolta_richieste_webrtc (ip_pubblico, porta_pubblica, Nome, peers, richieste_in_attesa, chiave, chiave_pubblica, gpg, fingerprint, password, alfabeto, session, BASE_DIR))
    
    A = True
    while A:
   #    ris = await asyncio.to_thread(input, "1: Visualizza tutti i peer online sulla rete | 2: Inserisci l'indirizzo:porta di un peer per contattarlo | 3: Attendi che qualcuno ti contatti")
        ris = await asyncio.to_thread(input, "1: Inserisci l'indirizzo:porta di un peer per contattarlo | 2: Attendi che qualcuno ti contatti | 3: visualizza i peer con cui hai già parlato")
   #    if ris == "1":
   #        online = gossip.lista_peers("online", peers)
   #        for o in online:
   #            print(o["nome"], " ip: ", o["ip"], "Porta: ", o["porta"])
        
        if ris == "1":
            os.system("cls" if os.name == "nt" else "clear")
            selection.print_information(Nome, ip_pubblico, porta_pubblica, tipo_nat, ip_privato, porta, Alg)
            
            ricerca = await asyncio.to_thread(input, "Inserisci l'username o l'ip:porta del destinatario: ")
            
            procedi = False
            ip_destinazione, porta_destinazione, username_target = None, None, None
            if ":" in ricerca:
                ip_destinazione, porta_destinazione = ricerca.split(":", 1)
                print(f"Cerco una corrispondenza per gli indirizzo e porta: {ricerca}")
                response = selection.ceck_indirizzo(ip_destinazione, porta_destinazione)
                if response == "OK":
                    ris = input("L'indirizzo cercato non risulta essere salvato sul server, questo significa che non è possibile verificare il fingerprint server-side, tento lo stesso di contattarlo? (y/n)")
                    if ris.lower() == "y":
                        procedi = True
                elif response.split(",", 2)[0] == "exists":
                    trash, username_target, fingerprint_destinatario = response.split(",", 3)
                    print(f"Corrispondenza trovata sul server per l'username '{username_target}': ")
                    print(f"Ip:porta associati: {ip_destinazione}:{porta_destinazione}")
                    print(f"Fingerprint associato: {fingerprint_destinatario}")
                    procedi = True
                
            else:
                username_target = ricerca
                print(f"Cerco una corrispondenza per l'username: {username_target}")
                response = selection.ceck_nome(username_target)
                if response == "OK":
                    print("Il nome non risulta essere salvato sul server, prova a contattare il dispositivo direttamente con il suo ip:porta")
                elif response.split(",", 3)[0] == "exists":
                    trash, ip_destinazione, porta_destinazione, fingerprint_destinatario = response.split(",", 3)
                    print(f"Corrispondenza trovata sul server per l'username '{username_target}': ")
                    print(f"Ip:porta associati: {ip_destinazione}:{porta_destinazione}")
                    print(f"Fingerprint associato: {fingerprint_destinatario}")
                    procedi = True
            
            if procedi == True:
                try:
                    print("Provo ad aprire una connessione diretta...")
                    await network.tenta_connessione_diretta(ip_destinazione, porta_destinazione, Nome, Alg, chiave_pubblica, chiave, alfabeto, gpg, password, session, username_target, fingerprint_destinatario)
                        
                except(ConnectionRefusedError, ConnectionResetError, asyncio.TimeoutError, OSError):
                    print("Peer irraggiungibile per via diretta, tento con webRTC...")
                    ricerca = ip_destinazione + ":" + str(porta_destinazione)
                    try:
                        await asyncio.wait_for(
                            network.tenta_connessione_webRTC(ip_pubblico, porta_pubblica, Nome, ricerca, peers, richieste_in_attesa, chiave, chiave_pubblica, gpg, fingerprint, password, alfabeto, session, Alg, username_target, fingerprint_destinatario, BASE_DIR),
                            timeout=30
                        )
                    except Exception as e:
                        print(f"\033[31m E' stato impossibile stabilire una connessione (WebRTC): {e} \033[0m")
                except Exception as e:
                    print(f"\033[31m E' stato impossibile stabilire una connessione: {e} \033[0m")

    #           except:
    #               print("Errore nella connessione, peer irraggiungibile con webRTC, tento con tailscale...")
    #               peers_ref = {(p["ip"], p["porta"]): p for p in peers}
    #               peers_ref[ip_destinazione, porta_destinazione]["stato"] = "unreachable"

        frase = f"In ascolto sulla porta {porta} "
        if ris == "2":
            selection.print_information(Nome, ip_pubblico, porta_pubblica, tipo_nat, ip_privato, porta, Alg)
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
                    print(testo)
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
                    selection.print_information(Nome, ip_pubblico, porta_pubblica, tipo_nat, ip_privato, porta, Alg)
                    frase = frase + "."
                    print(frase)
                    await asyncio.sleep(2)
        if ris == "3":
            with open(os.path.join(BASE_DIR, "known_hosts.json"), "r") as f:
                known_hosts = json.load(f)
            for h in known_hosts:
                print(h["nome"], " - ", h["fingerprint"])
                
    await task_server

asyncio.run(main())