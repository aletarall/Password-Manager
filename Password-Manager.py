import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog
from cryptography.fernet import Fernet
import os
import json
import bcrypt
import pyotp
import qrcode

#               .--.
#              /.-. '----------.
#              \'-' .--"--""-"-'
#               '--'
#Creato da Alessandro Nisi il 15/06/2024 mentre guardava la partita Italia - Albania


# Variabile globale per i tentativi di login
login_attempts = 0
# Variabile globale per il percorso di salvataggio
save_path = ""

def generate_key(file_name):
    key = Fernet.generate_key()
    with open(file_name, "wb") as key_file:
        key_file.write(key)

def load_key(file_name):
    return open(file_name, "rb").read()

def encrypt_password(password, key):
    f = Fernet(key)
    encrypted_password = f.encrypt(password.encode())
    return encrypted_password

def decrypt_password(encrypted_password, key):
    f = Fernet(key)
    decrypted_password = f.decrypt(encrypted_password).decode()
    return decrypted_password

def add_password(service, password, key, file_name):
    encrypted_password = encrypt_password(password, key)
    if os.path.exists(file_name):
        with open(file_name, "r") as file:
            passwords = json.load(file)
    else:
        passwords = {}
    
    passwords[service] = encrypted_password.decode()

    with open(file_name, "w") as file:
        json.dump(passwords, file)

def get_password(service, key, file_name):
    if os.path.exists(file_name):
        with open(file_name, "r") as file:
            passwords = json.load(file)
        
        if service in passwords:
            encrypted_password = passwords[service].encode()
            return decrypt_password(encrypted_password, key)
    
    return None

def delete_password(service, file_name):
    if os.path.exists(file_name):
        with open(file_name, "r") as file:
            passwords = json.load(file)
        
        if service in passwords:
            del passwords[service]
            with open(file_name, "w") as file:
                json.dump(passwords, file)
            return True
    
    return False

def update_password(service, new_password, key, file_name):
    if os.path.exists(file_name):
        with open(file_name, "r") as file:
            passwords = json.load(file)
        
        if service in passwords:
            encrypted_password = encrypt_password(new_password, key)
            passwords[service] = encrypted_password.decode()
            with open(file_name, "w") as file:
                json.dump(passwords, file)
            return True
    
    return False

def list_services(file_name):
    if os.path.exists(file_name):
        with open(file_name, "r") as file:
            passwords = json.load(file)
            services = list(passwords.keys())
            return services
    return []

def clear_all_data():
    global save_path
    confirm = messagebox.askyesno("Conferma", "Sei sicuro di voler cancellare tutti i dati?")
    if confirm:
        files_to_delete = [
            os.path.join(save_path, "secret1.key"),
            os.path.join(save_path, "secret2.key"),
            os.path.join(save_path, "passwords1.json"),
            os.path.join(save_path, "passwords2.json"),
            os.path.join(save_path, "login1.hash"),
            os.path.join(save_path, "login2.hash"),
            os.path.join(save_path, "otp_secret.json")
        ]
        for file in files_to_delete:
            if os.path.exists(file):
                os.remove(file)
        messagebox.showinfo("Successo", "Tutti i dati sono stati cancellati con successo!")
        os._exit(0)

def generate_otp_secret():
    return pyotp.random_base32()

def show_qr_code(secret, label):
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=label, issuer_name="Password Manager")
    qr = qrcode.make(uri)
    qr.show()

def center_window(root, width, height):
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width // 2) - (width // 2)
    y = (screen_height // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')

# Funzione per la schermata principale
def main_screen(key, file_name):
    root = tk.Tk()
    root.title("Password Manager")
    center_window(root, 600, 600)

    # Funzione per tornare alla schermata di login
    def return_to_login():
        root.destroy()
        login_screen()

    # Funzione per aggiungere una nuova password
    def add_password_gui():
        service = service_entry.get()
        password = password_entry.get()
        if service and password:
            add_password(service, password, key, file_name)
            messagebox.showinfo("Successo", "Password aggiunta con successo!")
        else:
            messagebox.showwarning("Errore", "Per favore inserisci tutti i campi.")

    # Funzione per recuperare una password
    def get_password_gui():
        service = service_entry.get()
        if service:
            password = get_password(service, key, file_name)
            if password:
                messagebox.showinfo("Risultato", f"La password per {service} è: {password}")
            else:
                messagebox.showwarning("Errore", "Servizio non trovato!")
        else:
            messagebox.showwarning("Errore", "Per favore inserisci il nome del servizio.")

    # Funzione per eliminare una password
    def delete_password_gui():
        service = service_entry.get()
        if service:
            if delete_password(service, file_name):
                messagebox.showinfo("Successo", "Password eliminata con successo!")
            else:
                messagebox.showwarning("Errore", "Servizio non trovato!")
        else:
            messagebox.showwarning("Errore", "Per favore inserisci il nome del servizio.")

    # Funzione per aggiornare una password
    def update_password_gui():
        service = service_entry.get()
        new_password = password_entry.get()
        if service and new_password:
            if update_password(service, new_password, key, file_name):
                messagebox.showinfo("Successo", "Password aggiornata con successo!")
            else:
                messagebox.showwarning("Errore", "Servizio non trovato!")
        else:
            messagebox.showwarning("Errore", "Per favore inserisci tutti i campi.")

    # Funzione per elencare tutti i servizi
    def list_services_gui():
        services = list_services(file_name)
        if services:
            services_list = "\n".join([f"{service}: {'*' * 4}" for service in services])
            messagebox.showinfo("Servizi Salvati", services_list)
        else:
            messagebox.showinfo("Servizi Salvati", "Nessun servizio trovato.")

    # Widget dell'interfaccia
    tk.Label(root, text="Nome del servizio:").pack(pady=5)
    service_entry = tk.Entry(root, width=40)
    service_entry.pack(pady=5)

    tk.Label(root, text="Password:").pack(pady=5)
    password_entry = tk.Entry(root, show="*", width=40)
    password_entry.pack(pady=5)

    add_button = tk.Button(root, text="Aggiungi Password", command=add_password_gui, width=20)
    add_button.pack(pady=5)

    get_button = tk.Button(root, text="Recupera Password", command=get_password_gui, width=20)
    get_button.pack(pady=5)

    delete_button = tk.Button(root, text="Elimina Password", command=delete_password_gui, width=20)
    delete_button.pack(pady=5)

    update_button = tk.Button(root, text="Aggiorna Password", command=update_password_gui, width=20)
    update_button.pack(pady=5)

    list_button = tk.Button(root, text="Elenca Servizi", command=list_services_gui, width=20)
    list_button.pack(pady=5)

    return_button = tk.Button(root, text="Torna al Login", command=return_to_login, width=20)
    return_button.pack(pady=5)

    clear_button = tk.Button(root, text="Cancella Tutto", command=clear_all_data, width=20)
    clear_button.pack(pady=5)

    close_button = tk.Button(root, text="Chiudi", command=root.destroy, width=20)
    close_button.pack(pady=5)

    root.mainloop()

# Funzione per la schermata di login
def login_screen():
    global login_attempts
    login_attempts = 0
    login_window = tk.Tk()
    login_window.title("Login")
    center_window(login_window, 400, 250)

    def check_password():
        global login_attempts
        entered_password = password_entry.get()
        entered_otp = otp_entry.get()

        if login_attempts >= 3:
            messagebox.showwarning("Errore", "Troppi tentativi falliti. Attendere 60 secondi.")
            login_window.after(60000, reset_login_attempts)
            return

        valid_password1 = validate_login_password(entered_password, os.path.join(save_path, "login1.hash"))
        valid_password2 = validate_login_password(entered_password, os.path.join(save_path, "login2.hash"))

        totp1 = pyotp.TOTP(otp_secret["account1"])
        totp2 = pyotp.TOTP(otp_secret["account2"])

        valid_otp1 = totp1.verify(entered_otp)
        valid_otp2 = totp2.verify(entered_otp)

        if valid_password1 and valid_otp1:
            login_window.destroy()
            main_screen(key1, os.path.join(save_path, "passwords1.json"))
        elif valid_password2 and valid_otp2:
            login_window.destroy()
            main_screen(key2, os.path.join(save_path, "passwords2.json"))
        else:
            login_attempts += 1
            messagebox.showwarning("Errore", "Password o OTP errato!")

    def reset_login_attempts():
        global login_attempts
        login_attempts = 0

    def validate_login_password(entered_password, hash_file):
        try:
            with open(hash_file, "rb") as file:
                stored_hash = file.read()
            return bcrypt.checkpw(entered_password.encode(), stored_hash)
        except FileNotFoundError:
            return False

    tk.Label(login_window, text="Inserisci la password:").pack(pady=5)
    password_entry = tk.Entry(login_window, show="*", width=30)
    password_entry.pack(pady=5)

    tk.Label(login_window, text="Inserisci il codice OTP:").pack(pady=5)
    otp_entry = tk.Entry(login_window, width=30)
    otp_entry.pack(pady=5)

    login_button = tk.Button(login_window, text="Login", command=check_password, width=15)
    login_button.pack(pady=5)

    close_button = tk.Button(login_window, text="Chiudi", command=login_window.destroy, width=15)
    close_button.pack(pady=5)

    login_window.mainloop()

# Funzione principale
def main():
    global save_path, key1, key2, otp_secret

    root = tk.Tk()
    root.withdraw()  # Nascondi la finestra principale mentre scegliamo il percorso

    save_path = filedialog.askdirectory(title="Seleziona la cartella per salvare i file")
    if not save_path:
        messagebox.showerror("Errore", "Devi selezionare una cartella per salvare i file.")
        return

    if not os.path.exists(os.path.join(save_path, "secret1.key")) or not os.path.exists(os.path.join(save_path, "secret2.key")):
        messagebox.showinfo("Setup", "Non sono stati trovati file di configurazione. Impostazione iniziale...")

        generate_key(os.path.join(save_path, "secret1.key"))
        generate_key(os.path.join(save_path, "secret2.key"))

        key1 = load_key(os.path.join(save_path, "secret1.key"))
        key2 = load_key(os.path.join(save_path, "secret2.key"))

        login1_password = simpledialog.askstring("Setup", "Inserisci la password principale per il login1:", show="*")
        login2_password = simpledialog.askstring("Setup", "Inserisci la password principale per il login2:", show="*")

        if not login1_password or not login2_password:
            messagebox.showerror("Errore", "Le password non possono essere vuote.")
            return

        hashed_login1_password = bcrypt.hashpw(login1_password.encode(), bcrypt.gensalt())
        hashed_login2_password = bcrypt.hashpw(login2_password.encode(), bcrypt.gensalt())

        with open(os.path.join(save_path, "login1.hash"), "wb") as file:
            file.write(hashed_login1_password)

        with open(os.path.join(save_path, "login2.hash"), "wb") as file:
            file.write(hashed_login2_password)

        otp_secret = {
            "account1": generate_otp_secret(),
            "account2": generate_otp_secret()
        }
        with open(os.path.join(save_path, "otp_secret.json"), "w") as file:
            json.dump(otp_secret, file)

        show_qr_code(otp_secret["account1"], "Account 1")
        show_qr_code(otp_secret["account2"], "Account 2")

        messagebox.showinfo("Setup Completato", "Setup completato con successo. Scansiona i codici QR con Google Authenticator e accedi con la tua password e codice OTP.")

    else:
        key1 = load_key(os.path.join(save_path, "secret1.key"))
        key2 = load_key(os.path.join(save_path, "secret2.key"))

        with open(os.path.join(save_path, "otp_secret.json"), "r") as file:
            otp_secret = json.load(file)

    login_screen()

if __name__ == "__main__":
    main()
