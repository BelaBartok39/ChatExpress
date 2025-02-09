import socket
import threading
import json
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import sys

# TODO: Clean up the interrupts to make exiting or lost connection graceful. (Might
#       need to ping each other every millisecond in the background to verify connection)
# TODO: Create a way to let users know if someone is trying to connect to them. (could require
#       persistent connection) Chat request feature?
# TODO: If there is time, consider a chat room similar to IRCs
# TODO: Create way to get info on incoming connections before accepting incoming chat request
# TODO: Allow for removing contacts
# TODO: 

CONTACTS_FILE = os.path.expanduser('~/.p2p_chat/contacts.json')

def display_title():
    print(r"""
   _____ _           _   ______      _     _       _   
  / ____| |         | | |  ____|    | |   | |     | |  
 | |    | |__   __ _| |_| |__  __  _| |__ | |_ ___| |_ 
 | |    | '_ \ / _` | __|  __| \ \/ / '_ \| __/ __| __|
 | |____| | | | (_| | |_| |____ >  <| |_) | || (__| |_ 
  \_____|_| |_|\__,_|\__|______/_/\_\_.__/ \__\___|\__|
                                                       
    """)

class ContactManager:
    def __init__(self):
        self.contacts = []
        self.load_contacts()

    def load_contacts(self):
        if not os.path.exists(CONTACTS_FILE):
            self.contacts = []
            return
        with open(CONTACTS_FILE, 'r') as f:
            self.contacts = json.load(f)

    def save_contacts(self):
        os.makedirs(os.path.dirname(CONTACTS_FILE), exist_ok=True)
        with open(CONTACTS_FILE, 'w') as f:
            json.dump(self.contacts, f)

    def add_contact(self, name, ip, port):
        self.contacts.append({'name': name, 'ip': ip, 'port': port})
        self.save_contacts()

    def list_contacts(self):
        return self.contacts

    def delete_contact(self, index):
        if 0 <= index < len(self.contacts):
            del self.contacts[index]
            self.save_contacts()

class EncryptionHandler:
    def generate_key_pair(self):
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    def serialize_public_key(self, public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def deserialize_public_key(self, public_key_bytes):
        return serialization.load_pem_public_key(
            public_key_bytes,
            backend=default_backend()
        )

    def derive_shared_key(self, private_key, peer_public_key):
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'chat-app-key',
            backend=default_backend()
        ).derive(shared_secret)
        return derived_key

    def encrypt_message(self, message, key):
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        return (nonce, ciphertext, encryptor.tag)

    def decrypt_message(self, nonce, ciphertext, tag, key):
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()

def handle_receive(conn, key, encryption_handler):
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                break
            nonce = data[:12]
            ciphertext = data[12:-16]
            tag = data[-16:]
            decrypted = encryption_handler.decrypt_message(nonce, ciphertext, tag, key)
            print(f"\nReceived: {decrypted}\n> ", end='')
        except:
            break
    conn.close()

def start_chat_session(conn, key, encryption_handler):
    receive_thread = threading.Thread(target=handle_receive, args=(conn, key, encryption_handler))
    receive_thread.start()
    while True:
        message = input("> ")
        if message.lower() == 'exit':
            break
        nonce, ciphertext, tag = encryption_handler.encrypt_message(message, key)
        conn.sendall(nonce + ciphertext + tag)
    conn.close()
    receive_thread.join()

def listen_for_connections(ip, port, encryption_handler):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((ip, port))
        s.listen()
        print(f"Listening on {ip}:{port}...")
        conn, addr = s.accept()
        print(f"Connected to {addr}")
        private_key, public_key = encryption_handler.generate_key_pair()
        conn.sendall(encryption_handler.serialize_public_key(public_key))
        peer_public_key_bytes = conn.recv(4096)
        peer_public_key = encryption_handler.deserialize_public_key(peer_public_key_bytes)
        shared_key = encryption_handler.derive_shared_key(private_key, peer_public_key)
        print("Secure connection established.")
        start_chat_session(conn, shared_key, encryption_handler)

def connect_to_peer(ip, port, encryption_handler):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((ip, port))
        print(f"Connected to {ip}:{port}")
        private_key, public_key = encryption_handler.generate_key_pair()
        peer_public_key_bytes = s.recv(4096)
        peer_public_key = encryption_handler.deserialize_public_key(peer_public_key_bytes)
        s.sendall(encryption_handler.serialize_public_key(public_key))
        shared_key = encryption_handler.derive_shared_key(private_key, peer_public_key)
        print("Secure connection established.")
        start_chat_session(s, shared_key, encryption_handler)

def main():
    display_title()
    contact_manager = ContactManager()
    encryption_handler = EncryptionHandler()

    while True:
        print("\nMain Menu:")
        print("1. Add Contact")
        print("2. List Contacts")
        print("3. Start Chat")
        print("4. Quit")
        choice = input("Choose an option: ")

        if choice == '1':
            name = input("Enter contact name: ")
            ip = input("Enter IP address: ")
            port = int(input("Enter port: "))
            contact_manager.add_contact(name, ip, port)
            print("Contact added.")
        elif choice == '2':
            contacts = contact_manager.list_contacts()
            for i, contact in enumerate(contacts):
                print(f"{i}: {contact['name']} - {contact['ip']}:{contact['port']}")
        elif choice == '3':
            contacts = contact_manager.list_contacts()
            if not contacts:
                print("No contacts available. Add a contact first.")
                continue
            for i, contact in enumerate(contacts):
                print(f"{i}: {contact['name']} - {contact['ip']}:{contact['port']}")
            contact_idx = int(input("Select contact: "))
            if contact_idx < 0 or contact_idx >= len(contacts):
                print("Invalid selection.")
                continue
            contact = contacts[contact_idx]
            action = input("Connect (c) or Wait for connection (w)? ")
            if action == 'c':
                connect_to_peer(contact['ip'], contact['port'], encryption_handler)
            elif action == 'w':
                listen_ip = input("Enter your IP to listen on: ")
                listen_port = int(input("Enter port to listen on: "))
                listen_for_connections(listen_ip, listen_port, encryption_handler)
            else:
                print("Invalid choice.")
        elif choice == '4':
            print("Exiting...")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
