# unseen





## Overview

unseen is an encrypted terminal chat application written in Python, based on a peer-to-peer model. The goal of the project is to minimize the level of trust that the user must place in the program, in order to ensure a secure and completely private exchange of messages.
 
Currently supported encryption algorithms:

\- **pgp**

In previous versions (for educational purposes only):

\- **Caesar**

\- **XOR**



> ⚠️ **It is not yet guaranteed to work remotely:**
I implemented a webRTC fallback for when the direct connection doesn't work, using a rendezvous server to exchange **only the information for the connection**, i'm working on implementing another fallback on tailscale if webrtc doesn't work. If encounter any problems in the remote communication you should use programs like hamachi or tailscale to create a p2p Vpn

> ⚠️ **Currently deprecated p2p gossip discovery method:**
I temporarily had to remove all the lines that activated the gossip discovery as i have to work on how to make it happen in remote

## Dependencies

This project requires **GnuPG (gpg)** to be installed on your local system, as the codebase relies on the underlying system binaries for the encryption of the messages.

pip install prompt_toolkit python-gnupg aiortc requests pystun3


## Versions

The project has evolved through multiple versions, and is currently at v5.x, these are the main improvements for each version:



* **v1.0** - First version of the program, without encryption, with basic functions for sending and receiving text and images
* **v2.0** - Caesar encryption was added. Images don't have it though.
* **v2.2** - Adding of .txt files to store server and client setup data, in this way the start is much faster.
* **v3.0** - Xor encryption was added. Images still don't have it lol.
* **v3.1** - Servers can now advertise themselves in broadcast on the LAN, and can be discovered by clients.
* **v4.0** - Added pgp encryption, and now you have one single python file, as the project became a real p2p chat.
* **v5.0** - Now you can contact peer from remote addresses, it's not guaranteed to work though (look at overview)



With each commit i'm trying to make the code better and more clean.