import time
import json
import asyncio
import random, requests
from . import network
import tempfile
import gnupg, os, base64
from aiortc import RTCPeerConnection, RTCSessionDescription, RTCConfiguration, RTCIceServer

config = RTCConfiguration(iceServers=[RTCIceServer(urls="stun:stun.l.google.com:19302")])
link_invio_dati = "http://mario404c.altervista.org/Secchat/invia.php"
link_richiesta_dati = "http://mario404c.altervista.org/Secchat/ricevi.php"
MAX_TENTATIVI = 24

def lista_peers(stato_richiesto, lista):
    if(stato_richiesto == "online"):
        return [p for p in lista if p["stato"] == "online"]
    elif(stato_richiesto == "offline"):
        return [p for p in lista if p["stato"] == "unreachable"]

class DataChannelWriter:
    def __init__(self, channel, peername=None):
        self._channel = channel
        self._peername = peername

    def write(self, data):
        if isinstance(data, str):
            data = data.encode()
        self._channel.send(data)

    async def drain(self):
        pass

    def get_extra_info(self, name, default=None):
        return default
    
    def close(self):
        if self._channel.readyState == "open":
            self._channel.close()

    async def wait_closed(self):
        while self._channel.readyState not in ("closed", "closing"):
            await asyncio.sleep(0.05)

def crea_reader_writer(channel, peername=None):
    reader = asyncio.StreamReader()

    @channel.on("message")
    def on_message(msg):
        if isinstance(msg, str):
            msg = msg.encode()
        reader.feed_data(msg)

    @channel.on("close")
    def on_close():
        reader.feed_eof()

    writer = DataChannelWriter(channel, peername=peername)
    return reader, writer

async def ascolta_richieste_webrtc(ip_personale, porta_personale, Nome, peers, richieste_in_attesa, chiave, chiave_pubblica, gpg, fingerprint, password, alfabeto, session, base_dir):
    ascolto = True
    while ascolto == True:
        ricerca = True
        while ricerca == True:
            await asyncio.sleep(2)
            response = requests.get(url = link_richiesta_dati).text
            Peers = response.splitlines()
            for riga in Peers:
                if not riga.strip():
                    continue
                Peer = riga.split(",")
                if len(Peer) < 7:
                    continue
                stringa = str(ip_personale) + ":" + str(porta_personale)
                if(Peer[4] == Nome or Peer[4] == stringa):
                    if(Peer[6] == "request"):
                        print(Peer[0]," ", Peer[1], " Vuole contattarti via webRTC")
                        indirizzo_offerente = Peer[1] + ":" + Peer[2]
                        blob_offerer = Peer[3]
                        
                        richiesta = {
                        "nome": Peer[0],
                        "indirizzo_client": Peer[1],
                        "decisione": None,
                        "tipo" : "webRTC"
                        }
                        richieste_in_attesa.append(richiesta)
                        
                        ricerca = False
                        

        while richiesta["decisione"] is None:
            await asyncio.sleep(1)
        
        if richiesta["decisione"] == "ACCETTATA":
            pc = RTCPeerConnection(configuration = config)

            canale = None
            reader = None
            writer = None

            @pc.on("datachannel")
            def on_datachannel(ch):
                nonlocal canale, reader, writer
                canale = ch
                reader, writer = crea_reader_writer(canale, peername=None)

            @pc.on("connectionstatechange")
            def on_state_change():
                print(pc.connectionState)
                
            
            dati = json.loads(base64.b64decode(blob_offerer).decode())
            sdp_ricevuto = dati["sdp"]
            tipo_ricevuto = dati["type"]                                            # forse si puo togliere dopo
            remote_desc = RTCSessionDescription(sdp=sdp_ricevuto, type="offer")
            await pc.setRemoteDescription(remote_desc)
            
            answer = await pc.createAnswer()
            await pc.setLocalDescription(answer)
            while pc.iceGatheringState != "complete":
                await asyncio.sleep(0.1)
                
            sdp_da_inviare = pc.localDescription.sdp    # stringa di testo (il contenuto SDP)
            tipo_da_inviare = pc.localDescription.type  # "offer" oppure "answer
            dati = json.dumps({"sdp": sdp_da_inviare, "type": tipo_da_inviare})
            blob_risposta = base64.b64encode(dati.encode()).decode()
            
            timestamp_inizio = float(time.time() + 10)
            payload = {
                "id": Nome,
                "ip": ip_personale,
                "porta": porta_personale,
                "blob": blob_risposta,
                "target": indirizzo_offerente,
                "timestamp": timestamp_inizio,
                "type": "answer"
                }
                
            requests.get(url = link_invio_dati, params = payload)
            
            attesa = timestamp_inizio - time.time()
            if attesa > 0:
                print(f"Attendo ancora {attesa} secondi per la sincronizzazione... ")
                await asyncio.sleep(attesa)
            else:
                print("Timestamp già passato, procedo subito")
            
            
            
            while pc.connectionState != "connected":
                if pc.connectionState == "failed":
                    print("Connessione fallita")
                    return  
                await asyncio.sleep(0.1)

            while canale is None:
                await asyncio.sleep(0.1)
                
                payload = {
                "id": Nome,
                "ip": ip_personale,
                "porta": porta_personale,
                "blob": "",
                "target": "",
                "timestamp": "",
                "type": "remove"
                }
                    
            requests.get(url = link_invio_dati, params = payload)                               # Pulisci server
            
            await gestisci_connessione(reader, writer, peers, richieste_in_attesa, chiave, chiave_pubblica, gpg, fingerprint, password, alfabeto, session, base_dir, tipo = "webrtc")
            ascolto = False
            
        else:
            print("Ho rifiutato la richiesta, continuo ad ascoltare...")
        

async def gestisci_connessione(reader, writer, peers, richieste_in_attesa, chiave, chiave_pubblica, gpg, fingerprint, password, alfabeto, session, base_dir, tipo):
    with open(os.path.join(base_dir, "config.txt"), "r") as f:
            righe = f.readlines()
                    
            righe = [riga.strip() for riga in righe]

            Nome = righe[0]
            Alg = righe[2]
    
    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=15.0)
    except asyncio.TimeoutError:
        print("Timeout: nessun messaggio ricevuto dall'offerer entro 15s")
        return
    
    if data.decode() == "GOSSIP_REQUEST":                                   # Richiesta gossip | Client --> Server
        # print(f" Richiesta di gossip da parte di: {indirizzo_client}")
        dati = json.dumps(peers).encode()
        writer.write(dati)
        await writer.drain()                                                    # Risposta con lista Peers | Client <-- Server

        data = await reader.read(65535)
        peers_ricevuti = json.loads(data.decode())                              # Ricezione lista peers | Client --> Server

        writer.close()
        await writer.wait_closed()

        ip_porta_noti = {(p["ip"], p["porta"]) for p in peers}
        for p in peers_ricevuti:
            if (p["ip"], p["porta"]) not in ip_porta_noti:
                peers.append(p)

        with open(os.path.join(base_dir, "ip_list.json"), "w") as f:
            json.dump(peers, f, indent=2)
        ricerca = False
            
    elif data.decode() == "CHAT_REQUEST":                # Richiesta chat | Client --> Server
        writer.write("OK_CHAT".encode())                 # Conferma | Client <-- Server
        await writer.drain()
        
        data = await reader.read(1024)
        Nome_client = data.decode()                      # Ricezione nome | Client --> Server
        print("Stai parlando con: ", Nome_client)
        
        writer.write(Nome.encode())                      # Invio nome | Client <-- Server
        await writer.drain()
        if tipo == "diretto":
            richiesta = {
            "nome": Nome_client,
            "indirizzo_client": writer.get_extra_info('peername'),
            "decisione": None,
            "tipo" : "connessione diretta"
            }
            richieste_in_attesa.append(richiesta)

            while richiesta["decisione"] is None:
                await asyncio.sleep(1)
        
        if tipo == "webrtc":
            richiesta = {
                "decisione": "ACCETTATA"
            }
        
        if richiesta["decisione"] == "ACCETTATA" or tipo == "webrtc":
            writer.write("ACCEPTED".encode())               # Invio conferma connessione accettata | Client <-- Server
            await writer.drain()
            
            data = await reader.read(1024)                  # Ricezione tipo alg | Client --> Server
            Alg_client = data.decode()
        
            if(Alg.lower() == "pgp" and Alg_client.lower() == "pgp"):
                writer.write("OK_PGP".encode())             # Conferma tipo alg | Client <-- Server
                await writer.drain()
                
                print("Avvio lo scambio di chiavi pubbliche...")
                
                lunghezza_bytes = await reader.readexactly(4)
                lunghezza = int.from_bytes(lunghezza_bytes, 'big')
                chiave_pubblica_client = (await reader.readexactly(lunghezza)).decode('utf-8')
                                                                                                # Scambio chiavi
                dati = chiave_pubblica.encode('utf-8')
                writer.write(len(dati).to_bytes(4, 'big') + dati)
                await writer.drain()
                
                with tempfile.TemporaryDirectory() as cartella_temp:
                    gpg_sessione = gnupg.GPG(gnupghome=cartella_temp)               # Keyring temporaneo
                    risultato = gpg_sessione.import_keys(chiave_pubblica_client)    # Import chiave pubblica client
                    fingerprint_client = risultato.fingerprints[0]

                    asyncio.create_task(network.ricevi(reader, writer, Nome_client, Alg, chiave, alfabeto, gpg, password))
                    await network.invia_async(reader, writer, Alg, chiave, gpg_sessione, fingerprint_client, alfabeto, session)
                
            elif(Alg.lower() !=  Alg_client.lower()):
                writer.write("ALG_MISMATCH".encode())            # Rifiuto tipo alg | Client <-- Server
                await writer.drain()
                print(f"Algoritmo incompatibile con {Nome_client}, lui usa {Alg_client}, connessione chiusa")
                writer.close()
                await writer.wait_closed()
            
            else:
                gpg_sessione = None
                fingerprint_client = None
                
            asyncio.create_task(network.ricevi(reader, writer, Nome_client, Alg, chiave, alfabeto, gpg, password))
            await network.invia_async(reader, writer, Alg, chiave, gpg_sessione, fingerprint_client, alfabeto, session)
            
        else:
            writer.write("REFUSED".encode())
            await writer.drain()

            


async def ascolto(porta, peers, richieste_in_attesa, chiave, chiave_pubblica, gpg, fingerprint, password, alfabeto, session, base_dir):
    server = await asyncio.start_server(
    lambda r, w: gestisci_connessione(r, w, peers, richieste_in_attesa, chiave, chiave_pubblica, gpg, fingerprint, password, alfabeto, session, base_dir, tipo = "diretto"),
    "", int(porta)
)
    
    async with server:
        await server.serve_forever()

async def gossip(peers, ip_personale, base_dir):
    while True:
        peers_online = lista_peers("online", peers)
        with open(os.path.join(base_dir, "config.txt"), "r") as f:
            righe = f.readlines()
            righe = [riga.strip() for riga in righe]
            Nome = righe[0]
            porta = int(righe[1])
            Alg = righe[2]
            ultimo_gossip = righe[3]
            fingerprint = righe[4]
            
        tempo_passato = time.time() - float(ultimo_gossip)
        await asyncio.sleep(1)
        if(tempo_passato > 5):
            # print("Sono passati 5 secondi o più")
            with open(os.path.join(base_dir, "config.txt"), "w") as f:
                f.write(f"{Nome}\n")
                f.write(f"{porta}\n")
                f.write(f"{Alg}\n")
                f.write(f"{time.time()}\n")
                f.write(f"{fingerprint}\n")

            if len(peers_online) < 3:
                numeri_randomici = list(range(len(peers_online)))
            else:
                numeri_randomici = random.sample(range(0, len(peers_online)), 3)    
            # print(numeri_randomici)

            for p in numeri_randomici:
                ip = peers_online[p]["ip"]
                port = peers_online[p]["porta"]

                if not (str(ip) == str(ip_personale) and str(port) == str(porta)):
                    
                    # print(f"Porta: {port}, ip: {ip}")

                    try:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(ip, int(port)), timeout=3
                        )
                        
                        peers_online[p]["timestamp"] = time.time()
                        
                        writer.write("GOSSIP_REQUEST".encode())         # Richiesta gossip | Client --> Server
                        await writer.drain()

                        data = await reader.read(65535)
                        peers_ricevuti = json.loads(data.decode())      # Ricezione lista peers | Client <-- Server

                        dati = json.dumps(peers).encode()
                        writer.write(dati)
                        await writer.drain()                            # Invio Lista peers | Client --> Server

                        writer.close()
                        await writer.wait_closed()
                        
                        peers_noti = {(p["ip"], p["porta"]): p for p in peers}
                        for pr in peers_ricevuti:
                            chiave = (pr["ip"], pr["porta"])
                            if chiave not in peers_noti:
                                peers.append(pr)
                            else:
                                if pr["timestamp"] > peers_noti[chiave]["timestamp"]:
                                    peers_noti[chiave]["stato"] = pr["stato"]
                                    peers_noti[chiave]["timestamp"] = pr["timestamp"]
                        
                    except (ConnectionRefusedError, ConnectionResetError, asyncio.TimeoutError, OSError):
                        peers_ref = {(p["ip"], p["porta"]): p for p in peers}
                        peers_ref[ip, port]["stato"] = "unreachable"
                        peers_ref[ip, port]["numero_tentativi"] = 1
                    
                with open(os.path.join(base_dir, "ip_list.json"), "w") as f:
                    json.dump(peers, f, indent=2)
                    
async def ceck_unreachable(peers, base_dir):
    while True:
        await asyncio.sleep(60)
        offline_peers = lista_peers("offline", peers)
        if len(offline_peers) > 0:
            for op in offline_peers:
                tempo_passato = time.time() - op.get("timestamp", time.time())
                if(tempo_passato > 900 * op.get("numero_tentativi", 1)): # 900 = 15 minuti
                    ip = op["ip"]
                    porta = op["porta"]
                    # print("provo a contattare", ip, "sulla porta ", porta, " per controllare se è tornato online")
                    try:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(ip, int(porta)), timeout=3
                        )
                        writer.close()
                        await writer.wait_closed()
                        esito = True
                    except (ConnectionRefusedError, ConnectionResetError, asyncio.TimeoutError, OSError):
                        esito = False
                    
                    peers_ref = {(p["ip"], p["porta"]): p for p in peers}
                    
                    if esito == True:
                        peers_ref[ip, porta]["stato"] = "online"
                        peers_ref[ip, porta]["timestamp"] = time.time()
                        del peers_ref[ip, porta]["numero_tentativi"]
                    elif esito == False:
                        if(peers_ref[ip, porta].get("numero_tentativi", 0) < MAX_TENTATIVI):
                            peers_ref[ip, porta]["numero_tentativi"] = peers_ref[ip, porta].get("numero_tentativi", 0) + 1
                            peers_ref[ip, porta]["timestamp"] = time.time()
                        else:
                            peers.remove(peers_ref[ip, porta])
        with open(os.path.join(base_dir, "ip_list.json"), "w") as f:
            json.dump(peers, f, indent=2)