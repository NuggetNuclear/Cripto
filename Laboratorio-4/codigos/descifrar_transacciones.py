import hashlib
from scapy.all import Raw, rdpcap
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA

PCAP_FILE = "transacciones_cifradas.pcap"
KEY_FILE = "clave_privada.pem"
TAG_RSA = b"RSA_PIN|"
TAG_AES = b"AESGCM|"
SALT_LEN = 16
NONCE_LEN = 12
GCM_TAG_LEN = 16

paquetes = rdpcap(PCAP_FILE)
payloadRsa = None
payloadsAes = []

for pkt in paquetes:
    if pkt.haslayer(Raw):
        datos = bytes(pkt[Raw].load)
        if datos.startswith(TAG_RSA) and payloadRsa is None:
            payloadRsa = datos[len(TAG_RSA) :]
        elif datos.startswith(TAG_AES):
            payloadsAes.append(datos[len(TAG_AES) :])

salt = payloadRsa[:SALT_LEN]
pinCifrado = payloadRsa[SALT_LEN:]

with open(KEY_FILE, "rb") as f:
    clavePriv = RSA.import_key(f.read())

oaep = PKCS1_OAEP.new(clavePriv, hashAlgo=SHA256)
pinBytes = oaep.decrypt(pinCifrado)
pin = pinBytes.decode("utf-8")

claveAes = hashlib.scrypt(pinBytes, salt=salt, n=2**14, r=8, p=1, dklen=32)

print("[+] PIN recuperado mediante RSA")
print(f"[+] PIN: {pin}")
print(f"[+] Salt: {salt.hex()}")
print(f"[+] Clave AES: {claveAes.hex()}")
print(f"[+] Transacciones cifradas encontradas: {len(payloadsAes)}\n")
print("========== TRANSACCIONES ==========")

for idx, cuerpo in enumerate(payloadsAes, start=1):
    nonce = cuerpo[:NONCE_LEN]
    ciphertext = cuerpo[NONCE_LEN:-GCM_TAG_LEN]
    tag = cuerpo[-GCM_TAG_LEN:]
    cifrador = AES.new(claveAes, AES.MODE_GCM, nonce=nonce)
    mensaje = cifrador.decrypt_and_verify(ciphertext, tag).decode("utf-8")
    print(f"\n[Transacción {idx}]")
    print(mensaje)
