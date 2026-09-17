import os, time
import base64, json, string, secrets
from aiortc import RTCPeerConnection, RTCSessionDescription, RTCConfiguration, RTCIceServer
import tempfile, gnupg
from . import gossip
from . import encryption
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
import asyncio
import requests

config = RTCConfiguration(iceServers=[RTCIceServer(urls="stun:stun.l.google.com:19302")])
link_invio_dati = "http://mario404c.altervista.org/Secchat/invia.php"
link_richiesta_dati = "http://mario404c.altervista.org/Secchat/ricevi.php"

# ----------------- FUNZIONI SOCKET -----------------

async def invia_messaggio(writer, testo):
    dati = testo.encode('utf-8')
    writer.write(len(dati).to_bytes(4, 'big') + dati)
    await writer.drain()
    
async def ricevi_messaggio(reader):
    lunghezza_bytes = await reader.readexactly(4)
    lunghezza = int.from_bytes(lunghezza_bytes, 'big')
    testo = (await reader.readexactly(lunghezza)).decode('utf-8')
    return testo

async def handshake_connessione(reader, writer, Nome, Alg, chiave_pubblica, fingerprint, chiave, alfabeto, gpg, password, session, ip_destinazione, porta_destinazione, username_target, fingerprint_destinatario):
    await invia_messaggio(writer, "CHAT_REQUEST")
    print(f"Richiesta chat inviata con successo a {ip_destinazione}, attendo conferma...")

    data = await ricevi_messaggio(reader)
    if(data == "OK_CHAT"):                     # Ricezione risposta | Client <-- Server

        await invia_messaggio(writer, Nome)                            # Invio Nome | Client --> Server

        Nome_ricevuto = await ricevi_messaggio(reader)                  # ricezione Nome | Client <-- Server
        
        await invia_messaggio(writer, fingerprint)            # Invio Fingerprint | Client --> Server

        fingerprint_ricevuto = await ricevi_messaggio(reader)                  # ricezione Fingerprint | Client <-- Server

        esito = await ricevi_messaggio(reader)                  # Ricezione esito | Client <-- Server

        ceck1 = False
        ceck2 = False
        if fingerprint_ricevuto == fingerprint_destinatario and Nome_ricevuto == username_target:
            Nome_server = username_target
            print(f"Username e fingerprint combaciano, procedo con l'autenticazione di {username_target} - {fingerprint_destinatario}")
            ceck1 = True
            
        if esito == "ACCEPTED" and ceck1 == True:
            print(f"Connessione accettata da {Nome_server}, ({ip_destinazione}:{porta_destinazione})")
            
            await invia_messaggio(writer, Alg)                  # Invio Alg | Client --> Server
            
            alg_server = await ricevi_messaggio(reader)          # Ricezione esito | Client <-- Serverù
            
            if(alg_server == "ALG_MISMATCH"):
                print(f"Algoritmo incompatibile con {Nome_server}, connessione chiusa")
                writer.close()
                await writer.wait_closed()
                return
            print(f"Algoritmo compatibile con {Nome_server}!")
            
            gpg_sessione = None
            fingerprint_server = None
            if (Alg.lower() == "pgp" and alg_server == "OK_PGP"):
                print("Avvio lo scambio di chiavi pubbliche...")
                
                await invia_messaggio(writer, chiave_pubblica)         # Invio chiave pubblica
                
                chiave_pubblica_server = await ricevi_messaggio(reader) #Ricezione chiave pubblica

                cartella_temp = tempfile.TemporaryDirectory()
                gpg_sessione = gnupg.GPG(gnupghome=cartella_temp.name)
                risultato_import = gpg_sessione.import_keys(chiave_pubblica_server)
                fingerprint_server = risultato_import.fingerprints[0]
                
                # Autenticazione con firma:
                if fingerprint_server == fingerprint_destinatario:
                    alfabeto = string.ascii_letters  # tutte le lettere: a-z e A-Z
                    frase_casuale = ''.join(secrets.choice(alfabeto) for _ in range(32))
                    
                    await invia_messaggio(writer, frase_casuale)                  # Invio frase casuale | Client --> Server

                    frase_casuale_ricevuta = await ricevi_messaggio(reader)                 # ricezione frase casuale | Client <-- Server

                    firma = gpg.sign(
                        frase_casuale_ricevuta,
                        keyid=fingerprint,
                        passphrase=password
                    )
                    
                    await invia_messaggio(writer, str(firma))       # Invio firma | Client ----> Server

                    firma_server = await ricevi_messaggio(reader)
                    
                    risultato = gpg_sessione.verify(str(firma_server))
                    contenuto = gpg_sessione.decrypt(str(firma_server))
                    testo_firmato = str(contenuto).strip()

                    if risultato.valid and testo_firmato == frase_casuale:
                        print(f"L'utente {username_target} si è autenticato correttamente")
                        ceck2 = True
                    else:
                        print(f"L'utente {username_target} non ha passato il processo di autenticazione, potresti star subendo un tentativo di attacco")
            else:
                print(f"L'utente {username_target} non ha passato il processo di autenticazione, il fingerprint non corrisponde!")
                    
            if ceck2 == True:
                print("\033[32m Connessione stabilita con ", username_target,"! \033[0m")
                asyncio.create_task(ricevi(reader, writer, Nome_server, Alg, chiave, alfabeto, gpg, password))
                await invia_async(reader, writer, Alg, chiave, gpg_sessione, fingerprint_server, alfabeto, session)
                A = False
            else:
                print("Torno al menu'...")
                
        elif esito == "REFUSED":
            print(f"Connessione rifiutata da {ip_destinazione}:{porta_destinazione}")
            
    else:
        print(f"Errore di connessione con {ip_destinazione}:{porta_destinazione}")



async def ricevi(reader, writer, NomeCli, Alg, chiave, alfabeto, gpg, password):
    while True:
        try:
            if Alg.lower() == "pgp":
                data = await reader.read(65535)
            else:
                data = await reader.read(1024)
                
            if not data:
                print("Connessione chiusa dal server")
                break
            
            else:
                chiper = data.decode()
                if Alg == "cesare":
                    chiaro = encryption.decripta_cesare(chiper, chiave, alfabeto)
                elif Alg == "xor":
                    chiaro = encryption.decripta_Xor(chiper, chiave)
                elif Alg.lower() =="pgp":
                    risultato = gpg.decrypt(chiper, passphrase=password)
                    if risultato.ok:
                        chiaro = risultato.data.decode('utf-8')
                    else:
                        print("Errore nella decrittazione del messaggio: ", risultato.status)
                    
                print(NomeCli, ": ", chiaro)
                
        except Exception as e:
            print("Errore ricezione:", e)
            break

async def invia_async(reader, writer, Alg, chiave, gpg_sessione, fingerprint_client, alfabeto, session):
    with patch_stdout():  
        while True:
            try:
                chiaro = await session.prompt_async("Tu: ")
            except (EOFError, KeyboardInterrupt):
                print("\nChiusura invio richiesta dall'utente")
                break
            if Alg == "cesare":
                chiper = encryption.cripta_cesare(chiaro, chiave, alfabeto)
            elif Alg == "xor":
                chiper = encryption.cripta_Xor(chiaro, chiave)
            elif Alg.lower() =="pgp":
                risultato = gpg_sessione.encrypt(chiaro, recipients=[fingerprint_client], always_trust=True)
                if risultato.ok:
                    chiper = str(risultato)
                else:
                    print("Errore nella cifratura del messaggio: ", risultato.status)
                    continue
            writer.write(chiper.encode())
            await writer.drain()

# ============================== webRTC ===================================
async def tenta_connessione_webRTC(indirizzo, porta, Nome, ricerca, peers, richieste_in_attesa, chiave, chiave_pubblica, gpg, fingerprint, password, alfabeto, session, Alg, base_dir):
    
    pc = RTCPeerConnection(configuration = config)
    channel = pc.createDataChannel("canale")
    reader, writer = gossip.crea_reader_writer(channel, peername=None)

    @pc.on("connectionstatechange")
    def on_state_change():
        return pc.connectionState
    
    offer = await pc.createOffer()
    await pc.setLocalDescription(offer)
    while pc.iceGatheringState != "complete":
        await asyncio.sleep(0.1)
    sdp_da_inviare = pc.localDescription.sdp    # contenuto SDP
    tipo_da_inviare = pc.localDescription.type  # "offer" oppure "answer"
    dati = json.dumps({"sdp": sdp_da_inviare, "type": tipo_da_inviare})
    blob_offerta = base64.b64encode(dati.encode()).decode() # codifica base64
    
    payload = {
        "id": Nome,
        "ip": indirizzo,
        "porta": porta,
        "blob": blob_offerta,
        "target": ricerca,
        "timestamp": "ask",
        "type": "request"
        }
        
    requests.get(url = link_invio_dati, params = payload)
    A = True
    while A == True:
        await asyncio.sleep(2)
        response = requests.get(url = link_richiesta_dati).text
        Peers = response.splitlines()
        for riga in Peers:
            if not riga.strip():
                continue
            Peer = riga.split(",")
            if len(Peer) < 7:
                continue
            stringa = str(indirizzo) + ":" + str(porta)
            if(Peer[4] == Nome or Peer[4] == stringa):
                if(Peer[6] == "answer"):
                    print(Peer[0]," ", Peer[1], " accetta la richiesta")
                    ip_destinazione = Peer[1]
                    porta_destinazione = Peer[2]
                    blob_answerer = Peer[3]
                    timestamp_inizio = Peer[5]
                    A = False
    
    dati = json.loads(base64.b64decode(blob_answerer).decode()) # decodifica sdp ricevuto da base64 ad ascii
    sdp_ricevuto = dati["sdp"]
    tipo_ricevuto = dati["type"]                                            # forse si puo togliere dopo
    remote_desc = RTCSessionDescription(sdp=sdp_ricevuto, type=tipo_ricevuto)
    await pc.setRemoteDescription(remote_desc)
    attesa = float(timestamp_inizio) - time.time()
    if attesa > 0:
        print(f"Attendo ancora {attesa} secondi per la sincronizzazione... ")
        await asyncio.sleep(attesa)
    else:
        print("Timestamp già passato, procedo subito (potrebbero esserci problemi con la sincronizzazione)... ")
    
    while pc.connectionState != "connected":
        if pc.connectionState == "failed":
            print("Connessione fallita")
            return
        await asyncio.sleep(0.1)
    
    payload = {
        "id": Nome,
        "ip": indirizzo,
        "porta": porta,
        "blob": "",
        "target": "",
        "timestamp": "",
        "type": "remove"
        }
            
    requests.get(url = link_invio_dati, params = payload)                               # Pulisci server
    
    await handshake_connessione(reader, writer, Nome, Alg, chiave_pubblica, chiave, alfabeto, gpg, password, session, ip_destinazione, porta_destinazione)
    
# ============================== webRTC ===================================
    

async def tenta_connessione_diretta(ip_destinazione, porta_destinazione, Nome, Alg, chiave_pubblica, chiave, alfabeto, gpg, password, session, username_target, fingerprint_destinatario):
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(ip_destinazione, porta_destinazione), timeout=10
    )
    await handshake_connessione(reader, writer, Nome, Alg, chiave_pubblica, chiave, alfabeto, gpg, password, session, ip_destinazione, porta_destinazione, username_target, fingerprint_destinatario)