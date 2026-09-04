#!/usr/bin/env python3
"""
Laboratorio 1 - Actividad 2.1: Algoritmo de cifrado César
"""
import sys

def cesar_cipher(text: str, shift: int) -> str:
    result = []
    shift = shift % 26
    for char in text:
        if 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
        else:
            result.append(char)
    return "".join(result)

def main():
    if len(sys.argv) < 3:
        print("Uso: python3 cesar.py <texto> <corrimiento>")
        sys.exit(1)
    
    text = sys.argv[1]
    try:
        shift = int(sys.argv[2])
    except ValueError:
        print("Error: El corrimiento debe ser un número entero.")
        sys.exit(1)
        
    encrypted = cesar_cipher(text, shift)
    print(encrypted)

if __name__ == "__main__":
    main()

