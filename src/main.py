import os
import json
import re
import subprocess
import argparse

# Configuration des arguments
parser = argparse.ArgumentParser()
parser.add_argument("file", type=str, help="Chemin vers le fichier Solidity.")

def get_solidity_version(sol_file):
    """
    Extrait la version de Solidity à partir de la directive 'pragma solidity'.

    Args:
        sol_file (str): Chemin vers le fichier Solidity.

    Returns:
        str: Version de Solidity (ex: '0.8.13').
    """
    try:
        with open(sol_file, "r") as f:
            content = f.read()
        
        # Expression régulière pour trouver la version dans pragma solidity
        match = re.search(r'pragma solidity [\^~]*([\d.]+);', content)
        if match:
            return match.group(1)
        else:
            print("Aucune directive 'pragma solidity' trouvée dans le fichier.")
            return None
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier : {e}")
        return None

def select_solc_version(version):
    """
    Sélectionne la version de Solidity via solc-select.

    Args:
        version (str): Version de Solidity (ex: '0.8.13').

    Returns:
        bool: True si la version a été sélectionnée avec succès, sinon False.
    """
    try:
        subprocess.run(["solc-select", "use", version], check=True, capture_output=True, text=True)
        print(f"Version Solidity {version} sélectionnée avec succès.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Erreur : impossible de sélectionner la version {version}.")
        print(e.stderr)
        return False

def generate_ast(sol_file):
    """
    Génère l'AST compact JSON d'un fichier Solidity à l'aide de solc.

    Args:
        sol_file (str): Chemin vers le fichier Solidity.

    Returns:
        dict: AST sous forme de dictionnaire JSON.
    """
    try:
        # Exécution de la commande solc pour l'AST
        result = subprocess.run(["solc", "--ast-compact-json", sol_file],
                                capture_output=True, text=True, check=True)

        # Extraction du JSON avec une regex
        json_match = re.search(r'\{.*\}', result.stdout, re.DOTALL)
        if json_match:
            return json.loads(json_match.group(0))
        else:
            print("Erreur : JSON non trouvé dans la sortie de solc.")
            return None
    except subprocess.CalledProcessError as e:
        print("Erreur avec solc :")
        print(e.stderr)
        return None
    except json.JSONDecodeError as e:
        print("Erreur de décodage JSON :", e)
        return None

def main(sol_file):
    """
    Fonction principale : détecte la version, sélectionne solc et génère l'AST.
    """
    # Étape 1 : Extraire la version
    version = get_solidity_version(sol_file)
    if not version:
        print("Impossible de continuer sans version Solidity.")
        return

    # Étape 2 : Sélectionner la version via solc-select
    if not select_solc_version(version):
        print("La sélection de la version Solidity a échoué.")
        return

    # Étape 3 : Générer l'AST
    ast = generate_ast(sol_file)
    if ast:
        print("AST JSON généré avec succès :")
        print(json.dumps(ast, indent=4))
    else:
        print("Échec de la génération de l'AST.")

# Lancer le script
if __name__ == "__main__":
    args = parser.parse_args()
    main(args.file)
