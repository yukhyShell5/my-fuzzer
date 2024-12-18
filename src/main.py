import os
import json
import re
import subprocess
import argparse
import logging
import coloredlogs
import toml

# Configuration de logging avec couleurs
coloredlogs.install(level='INFO', fmt='%(asctime)s - %(levelname)s - %(message)s')

parser = argparse.ArgumentParser()
parser.add_argument("--file", type=str, help="Chemin vers le fichier Solidity.")
parser.add_argument("--framework", type=str, choices=["foundry", "hardhat"], help="Spécifie le framework utilisé (foundry ou hardhat).")

def is_solc_installed():
    try:
        subprocess.run(["solc", "--version"], capture_output=True, text=True, check=True)
        return True
    except FileNotFoundError:
        logging.warning("solc n'est pas installé. Tentative d'installation de solc-select via pip...")
        try:
            subprocess.run(["pip", "install", "solc-select"], check=True)
            logging.info("solc-select installé avec succès.")
            try:
                subprocess.run(["solc-select", "install", "all"], check=True)
                logging.info("Toutes les versions disponibles de solc ont été installées avec solc-select.")
                return True
            except subprocess.CalledProcessError:
                logging.error("Erreur : impossible d'installer les versions de solc avec solc-select.")
                return False
        except subprocess.CalledProcessError:
            logging.error("Erreur : impossible d'installer solc-select avec pip.")
            return False
    except subprocess.CalledProcessError:
        return False

def is_in_framework(specific_framework=None):
    """Vérifie si le script est exécuté dans un environnement Foundry ou Hardhat."""
    frameworks = {
        "foundry": "foundry.toml",
        "hardhat": ["hardhat.config.js", "hardhat.config.ts"]
    }

    if specific_framework:
        config_files = frameworks.get(specific_framework)
        if not config_files:
            return False
        if isinstance(config_files, list):
            return any(os.path.isfile(file) for file in config_files)
        return os.path.isfile(config_files)

    # Si aucun framework spécifique n'est demandé, chercher tous les frameworks possibles.
    detected_frameworks = [
        framework for framework, config_files in frameworks.items()
        if any(os.path.isfile(file) for file in (config_files if isinstance(config_files, list) else [config_files]))
    ]
    return detected_frameworks

def get_solidity_version(sol_file):
    try:
        with open(sol_file, "r") as f:
            content = f.read()
        match = re.search(r'pragma solidity [\^~]*([\d.]+);', content)
        if match:
            return match.group(1)
        return None
    except Exception as e:
        logging.error(f"Erreur lors de la lecture du fichier Solidity : {e}")
        return None

def select_solc_version(version):
    try:
        subprocess.run(["solc-select", "use", version], check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError:
        logging.error(f"Erreur : impossible de sélectionner la version {version}.")
        return False

def generate_ast(sol_file):
    try:
        result = subprocess.run(["solc", "--ast-compact-json", sol_file], capture_output=True, text=True, check=True)
        json_match = re.search(r'\{.*\}', result.stdout, re.DOTALL)
        if json_match:
            return json.loads(json_match.group(0))
        return None
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        logging.error("Erreur : échec de la génération de l'AST.")
        return None

def get_solidity_files_from_foundry():
    try:
        # Charger le fichier foundry.toml
        with open("foundry.toml", "r") as f:
            config = toml.load(f)
        
        # Lire le chemin du répertoire source dans la configuration
        src_directory = config.get("profile", {}).get("default", {}).get("src", "")
        
        if src_directory and os.path.isdir(src_directory):
            # Lire tous les fichiers Solidity dans le répertoire
            sol_files = [os.path.join(src_directory, f) for f in os.listdir(src_directory) if f.endswith(".sol")]
            return sol_files
        else:
            logging.error("Répertoire source non spécifié ou invalide dans foundry.toml.")
            return []
    except (FileNotFoundError, toml.TomlDecodeError) as e:
        logging.error(f"Erreur lors de la lecture de foundry.toml : {e}")
        return []

def main(sol_file, framework_arg):
    # Affiche le répertoire de travail actuel
    current_directory = os.getcwd()
    logging.info(f"Le script est exécuté dans le répertoire : {current_directory}")
    
    if framework_arg:
        # Si un framework spécifique est demandé
        if is_in_framework(framework_arg):
            logging.info(f"Environnement {framework_arg} détecté.")
        else:
            logging.error(f"Erreur : environnement {framework_arg} non détecté.")
            return
    else:
        # Sinon, détecter tous les frameworks
        detected_frameworks = is_in_framework()
        if detected_frameworks:
            logging.info(f"Environnements détectés : {', '.join(detected_frameworks)}.")
        else:
            logging.warning("Aucun environnement de framework spécifique détecté.")
    
    if framework_arg == "foundry":
        # Si Foundry est détecté et qu'un fichier est spécifié
        if sol_file:
            if os.path.isfile(sol_file):
                version = get_solidity_version(sol_file)
                if version:
                    logging.info(f"Version de Solidity pour {sol_file} : {version}")
                    if select_solc_version(version):
                        ast = generate_ast(sol_file)
                        if ast:
                            logging.info(f"AST générée pour {sol_file} avec succès.")
                            logging.debug(json.dumps(ast, indent=4))  # Utilise debug pour afficher l'AST en détails
                        else:
                            logging.error(f"Erreur : échec de la génération de l'AST pour {sol_file}.")
                    else:
                        logging.error(f"Erreur : impossible de sélectionner la version {version}.")
                else:
                    logging.error(f"Erreur : impossible de détecter la version de Solidity pour {sol_file}.")
            else:
                logging.error(f"Le fichier spécifié {sol_file} n'a pas été trouvé dans le répertoire Foundry.")
        else:
            # Sinon, générer l'AST pour tous les fichiers Solidity trouvés dans Foundry
            sol_files = get_solidity_files_from_foundry()
            if sol_files:
                logging.info(f"Fichiers Solidity trouvés dans Foundry : {', '.join(sol_files)}")
                for sol_file in sol_files:
                    version = get_solidity_version(sol_file)
                    if version:
                        logging.info(f"Version de Solidity pour {sol_file} : {version}")
                        if select_solc_version(version):
                            ast = generate_ast(sol_file)
                            if ast:
                                logging.info(f"AST générée pour {sol_file} avec succès.")
                                logging.debug(json.dumps(ast, indent=4))  # Utilise debug pour afficher l'AST en détails
                            else:
                                logging.error(f"Erreur : échec de la génération de l'AST pour {sol_file}.")
                        else:
                            logging.error(f"Erreur : impossible de sélectionner la version {version}.")
                    else:
                        logging.error(f"Erreur : impossible de détecter la version de Solidity pour {sol_file}.")
            else:
                logging.error("Aucun fichier Solidity trouvé dans Foundry.")
        return
    
    if not is_solc_installed():
        logging.error("Erreur : solc n'a pas pu être installé.")
        return
    version = get_solidity_version(sol_file)
    if not version:
        logging.error("Erreur : impossible de détecter la version de Solidity.")
        return
    if not select_solc_version(version):
        logging.error(f"Erreur : impossible de sélectionner la version {version}.")
        return
    ast = generate_ast(sol_file)
    if ast:
        logging.info("AST générée avec succès.")
        logging.debug(json.dumps(ast, indent=4))  # Utilise debug pour afficher l'AST en détails
    else:
        logging.error("Erreur : échec de la génération de l'AST.")

if __name__ == "__main__":
    args = parser.parse_args()
    main(args.file, args.framework)
