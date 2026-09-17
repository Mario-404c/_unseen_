
# ----------------- FUNZIONI CRITTOGRAFIA -----------------

def crea_chiave(password):
    chiave = ""
    for c in password:
        char = c
        codice = ord(char)
        chiave = chiave + str(codice)
    chiave = (int(chiave) / 2) * 4
    chiave = int(chiave)
    return str(chiave)

#       --Cesare--

def cripta_cesare(mess, chiave, alfabeto):
    while len(chiave) < len(mess):
        if len(str(chiave)) > len(mess):
            chiave = chiave
        else:
            chiave = chiave + chiave
    i = 0
    chiper = ""
    for c in mess:
        posizA = alfabeto.index(c)
        posizB = int(chiave[i])
        newposizA = (posizA + posizB) % 97
        chiper += alfabeto[newposizA]
        i += 1
    return chiper

def decripta_cesare(chiper, chiave, alfabeto):
    while len(chiave) < len(chiper):
        if len(str(chiave)) > len(chiper):
            chiave = chiave
        else:
            chiave = chiave + chiave
    frasedecrypt = ""
    for idx, c in enumerate(chiper):
        posizA = alfabeto.index(c)
        posizB = int(chiave[idx])
        newposizA = (posizA - posizB) % 97
        frasedecrypt += alfabeto[newposizA]
    return frasedecrypt

#       --Cesare--
#         --Xor--

def cripta_Xor(mess, Key):
    Lista_bit_parola = []
    Lista_bit_chiave = []
    Lista_bit_chiper = []

    Lista_bit_parola.clear()
    Lista_bit_chiave.clear()
    Lista_bit_chiper.clear()

    lunghezza_Parola = len(mess) * 2
    while len(str(Key)) < lunghezza_Parola:
        Key = Key + Key

    for c in mess:
        c_byte = c.encode("utf-8")[0]
        c_bits = format(c_byte, "08b")
        Lista_bit_parola.append(c_bits)

    i = 0
    while i < len(str(Key)):
        coppia = str(Key)[i:i+2]
        c_bits = format(int(coppia), "08b")
        Lista_bit_chiave.append(c_bits)
        i = i + 2
        
    for i in range(len(Lista_bit_parola)):
        parola = Lista_bit_parola[i]
        chiave = Lista_bit_chiave[i]
        
        xor_riga = ""
        for j in range(len(parola)):
            xor_bit = str(int(parola[j]) ^ int(chiave[j]))
            xor_riga += xor_bit
        
        Lista_bit_chiper.append(xor_riga)

    Lista_bit_chiper = [riga * 2 for riga in Lista_bit_chiper]

    mess_chiper = ""
    for r in Lista_bit_chiper:
        numero = int(r, 2)
        mess_chiper = mess_chiper + chr(numero)
    
    return mess_chiper

def decripta_Xor(chiper, Key):
    Lista_numeri_unicode = []
    Lista_bit_numeri_unicode = []
    Lista_bit_key = []
    Lista_bit_xor = []

    Lista_numeri_unicode.clear()
    Lista_bit_numeri_unicode.clear()
    Lista_bit_key.clear()
    Lista_bit_xor.clear()

    lunghezza_chiper = len(chiper) * 2
    while len(str(Key)) < lunghezza_chiper:
        Key = Key + Key

    for c in chiper:
        Lista_numeri_unicode.append(ord(c))
        
    for c in Lista_numeri_unicode:
        bits = format(int(c), "016b")
        
        Lista_bit_numeri_unicode.append(bits)

    i=0
    while i <  len(str(Key)):
        coppia = str(Key)[i:i+2]
        bit = format(int(coppia), "08b")
        Lista_bit_key.append(bit)
        i = i+2

    Lista_bit_key = [riga * 2 for riga in Lista_bit_key]


    for i in range(len(Lista_bit_numeri_unicode)):
        parola = Lista_bit_numeri_unicode[i]
        chiave = Lista_bit_key[i]
        
        xor_riga = ""
        for j in range(len(parola)):
            xor_bit = str(int(parola[j]) ^ int(chiave[j]))
            xor_riga += xor_bit
        
        Lista_bit_xor.append(xor_riga)

    mess_decrypt = ""

    for e in Lista_bit_xor:
        bit = e[:8]
        numero = int(bit, 2)
        mess_decrypt = mess_decrypt + chr(numero)
    
    return mess_decrypt
#         --Xor--