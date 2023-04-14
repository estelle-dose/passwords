import json
import hashlib
import re

def hash_password(password):
    """
    Fonction qui hache le mot de passe fourni en utilisant l'algorithme SHA-256.
    Retourne le mot de passe haché sous forme de chaîne de caractères.
    """
    return hashlib.sha256(password.encode()).hexdigest()

def save_passwords(passwords):
    """
    Fonction qui enregistre les mots de passe dans un fichier JSON.
    """
    with open('passwords2.json', 'w') as f:
        json.dump(list(passwords.keys()), f, indent=2)

def load_passwords():
    """
    Fonction qui charge les mots de passe depuis un fichier JSON.
    Retourne un dictionnaire contenant les mots de passe.
    """
    try:
        with open('passwords2.json', 'r') as f:
            return {password: None for password in json.load(f)}
    except FileNotFoundError:
        return {}

def add_password():
    """
    Fonction qui permet à l'utilisateur d'ajouter un nouveau mot de passe.
    """
    passwords = load_passwords()

    while True:
        password = input("Entrez un nouveau mot de passe (ou 'q' pour quitter) : ")
        if password == 'q':
            break

        # Vérification de la sécurité du mot de passe
        if len(password) < 8:
            print("Le mot de passe doit contenir au moins 8 caractères.")
            continue
        if not re.search("[a-z]", password):
            print("Le mot de passe doit contenir au moins une lettre minuscule.")
            continue
        if not re.search("[A-Z]", password):
            print("Le mot de passe doit contenir au moins une lettre majuscule.")
            continue
        if not re.search("[0-9]", password):
            print("Le mot de passe doit contenir au moins un chiffre.")
            continue
        if not re.search("[!@#$%^&*]", password):
            print("Le mot de passe doit contenir au moins un caractère spécial (!, @, #, $, %, ^, &, *).")
            continue
        
        hashed_password = hash_password(password)

        if hashed_password in passwords:
            print("Le mot de passe existe déjà.")
        else:
            passwords[hashed_password] = ''
            print(f"Le mot de passe {password} a été enregistré avec succès !")

        save_passwords(passwords)

def show_passwords():
    """
    Fonction qui affiche les mots de passe enregistrés.
    """
    passwords = load_passwords()
    if not passwords:
        print("Aucun mot de passe enregistré.")
    else:
        for hashed_password in passwords:
            print(hashed_password)

while True:
    action = input("Que voulez-vous faire ? ('a' pour ajouter un mot de passe, 's' pour afficher les mots de passe, 'q' pour quitter) : ")
    if action == 'q':
        break
    elif action == 'a':
        add_password()
    elif action == 's':
        show_passwords()
    else:
        print("Action invalide. Veuillez réessayer.")