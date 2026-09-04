#!/usr/bin/env python3
"""
Laboratorio 1 - Actividad 2.3: MitM (Lectura de pcapng y Criptoanálisis César)
Lee la captura de paquetes ICMP, extrae los datos encubiertos y genera los 26 corrimientos posibles.
La opción más probable de ser el mensaje en claro se resalta en verde.
"""
import sys
import string
from scapy.all import rdpcap, ICMP, Raw

# Diccionario de palabras comunes en español para puntuación
SPANISH_WORDS = {
    "criptografia", "seguridad", "redes", "red", "datos", "informacion",
    "de", "la", "que", "el", "en", "y", "a", "los", "se", "del", "las",
    "un", "por", "con", "no", "una", "su", "para", "es", "al", "lo",
    "como", "mas", "o", "pero", "sus", "le", "ha", "me", "si", "sin",
    "sobre", "este", "ya", "entre", "cuando", "todo", "esta", "ser",
    "son", "dos", "tambien", "era", "muy", "hasta", "desde", "mi"
}

# Frecuencias relativas típicas de letras en español
SPANISH_FREQ = {
    'e': 13.68, 'a': 12.53, 'o': 8.68, 's': 7.98, 'r': 6.87, 'n': 6.71,
    'i': 6.25, 'd': 5.86, 'l': 4.97, 'c': 4.68, 't': 4.63, 'u': 3.93,
    'm': 3.15, 'p': 2.51, 'b': 1.42, 'g': 1.01, 'v': 0.90, 'y': 0.90,
    'q': 0.88, 'h': 0.70, 'f': 0.69, 'z': 0.52, 'j': 0.44, 'x': 0.22,
    'w': 0.01, 'k': 0.01
}

def extract_covert_message(pcap_path: str) -> str:
    packets = rdpcap(pcap_path)
    # Agrupar paquetes por ICMP ID (identificador de sesión de ping)
    sessions = {}
    
    for pkt in packets:
        # Filtrar únicamente paquetes ICMP Echo Request (type 8)
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8 and pkt.haslayer(Raw):
            load = bytes(pkt[Raw].load)
            icmp_id = pkt[ICMP].id
            seq = pkt[ICMP].seq
            
            if len(load) >= 9:
                if icmp_id not in sessions:
                    sessions[icmp_id] = {}
                if seq not in sessions[icmp_id]:
                    sessions[icmp_id][seq] = chr(load[8])
                    
    if not sessions:
        return ""
        
    # Seleccionar la sesión con más paquetes (la de exfiltración)
    best_session = max(sessions.values(), key=len)
    
    # Ordenar los caracteres por su número de secuencia ICMP
    sorted_seqs = sorted(best_session.keys())
    return "".join(best_session[s] for s in sorted_seqs)

def caesar_decrypt(ciphertext: str, shift: int) -> str:
    result = []
    for char in ciphertext:
        if 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') - shift) % 26 + ord('A')))
        else:
            result.append(char)
    return "".join(result)

def score_spanish(text: str) -> float:
    words = text.lower().split()
    word_score = 0.0
    for w in words:
        clean_w = "".join(c for c in w if c in string.ascii_lowercase)
        if clean_w in SPANISH_WORDS:
            word_score += 150.0
            
    freq_score = 0.0
    total_letters = 0
    for c in text.lower():
        if c in SPANISH_FREQ:
            freq_score += SPANISH_FREQ[c]
            total_letters += 1
            
    if total_letters > 0:
        freq_score /= total_letters
        
    return word_score + freq_score

def main():
    if len(sys.argv) < 2:
        print("Uso: sudo python3 readv2.py <archivo.pcapng>")
        sys.exit(1)
        
    pcap_file = sys.argv[1]
    
    try:
        ciphertext = extract_covert_message(pcap_file)
    except Exception as e:
        print(f"Error al leer archivo de captura {pcap_file}: {e}")
        sys.exit(1)
        
    if not ciphertext:
        print("No se encontraron caracteres transmitidos en paquetes ICMP Echo Request.")
        sys.exit(1)
        
    # Calcular las 26 variantes y puntajes
    candidates = []
    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        score = score_spanish(decrypted)
        candidates.append((shift, decrypted, score))
        
    # Identificar la opción con mayor puntuación de claridad en español
    best_shift = max(candidates, key=lambda x: x[2])[0]
    
    # Imprimir todas las combinaciones, resaltando en verde la más probable
    GREEN = "\033[92m"
    RESET = "\033[0m"
    
    for shift, text, _ in candidates:
        line_prefix = f"{shift:<2}"
        if shift == best_shift:
            print(f"{GREEN}{line_prefix} {text}{RESET}")
        else:
            print(f"{line_prefix} {text}")

if __name__ == "__main__":
    main()
