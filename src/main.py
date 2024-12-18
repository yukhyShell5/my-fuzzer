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
parser.add_argument("--lib", type=str, help="Spécifie une bibliothèque à installer pour les imports.")
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

def install_solidity_imports(sol_file, extra_lib=None):
    """Installe les imports dans les fichiers Solidity si nécessaire, pour Foundry."""
    try:
        # Lire le contenu du fichier Solidity pour extraire les imports
        with open(sol_file, "r") as f:
            content = f.read()
        
        # Trouver les imports Solidity dans le fichier
        imports = re.findall(r'import\s+"([^"]+)";', content)
        
        if imports:
            logging.info(f"Imports trouvés dans {sol_file} : {', '.join(imports)}")
            
            # Pour chaque import trouvé, vérifier s'il est disponible et installer via Foundry
            for imp in imports:
                # Vérifie si le répertoire de l'import existe déjà
                if not os.path.isdir(os.path.join("lib", imp)):
                    logging.info(f"Installation de l'import {imp}...")
                    subprocess.run(["forge", "install", imp], check=True)
                else:
                    logging.info(f"L'import {imp} est déjà installé.")
        else:
            logging.info(f"Aucun import trouvé dans {sol_file}.")
        
        # Installer une bibliothèque supplémentaire si spécifiée
        if extra_lib:
            logging.info(f"Installation de la bibliothèque supplémentaire : {extra_lib}...")
            subprocess.run(["forge", "install", extra_lib], check=True)
        
    except Exception as e:
        logging.error(f"Erreur lors de l'installation des imports pour {sol_file} : {e}")

def extract_functions_recursively(nodes):
    """Récupère toutes les fonctions publiques ou externes dans l'AST."""
    functions = []
    for node in nodes:
        if node.get("nodeType") == "FunctionDefinition":
            visibility = node.get("visibility", "internal")
            function_name = node.get("name")
            if function_name and visibility in ["public", "external"]:
                functions.append(function_name)
        # Si le nœud contient des enfants, les parcourir récursivement
        if "nodes" in node:
            functions.extend(extract_functions_recursively(node["nodes"]))
    return functions

def generate_fuzzing_test(ast, contract_name="FuzzContract"):
    """Génère un fichier de test avec des appels pour fuzz les fonctions repérées dans l'AST."""
    # Extraire les fonctions publiques et externes
    functions = extract_functions_recursively(ast.get("nodes", []))
    
    if not functions:
        logging.warning("Aucune fonction publique ou externe trouvée dans l'AST.")
    
    # Générer le contenu du fichier de test
    test_content = f"""
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.0;

    import "forge-std/Test.sol";

    contract {contract_name} is Test {{
    """
    for func in functions:
        test_content += f"""
        function test_{func}() public {{
            // Fuzzer appelle {func}
            vm.prank(address(0x1));
            try this.{func}() {{
                assertTrue(true);
            }} catch {{
                assertTrue(false);
            }}
        }}
        """
    
    test_content += """
    }
    """

    # Construire le chemin de sauvegarde
    test_directory = os.path.join(os.getcwd(), 'test')
    os.makedirs(test_directory, exist_ok=True)
    test_file_path = os.path.join(test_directory, f"{contract_name}.sol")

    # Sauvegarder le fichier de test
    with open(test_file_path, "w") as f:
        f.write(test_content)
    
    logging.info(f"Fichier de test généré avec succès : {test_file_path}")

def main(sol_file, framework_arg=None, extra_lib=None):
    # Affiche le répertoire de travail actuel
    current_directory = os.getcwd()
    logging.info(f"Le script est exécuté dans le répertoire : {current_directory}")
    
    detected_frameworks = []
    
    if framework_arg:
        # Si un framework spécifique est demandé
        if is_in_framework(framework_arg):
            logging.info(f"Environnement {framework_arg} détecté.")
            detected_frameworks = [framework_arg]
        else:
            logging.error(f"Erreur : environnement {framework_arg} non détecté.")
            return
    else:
        # Sinon, détecter tous les frameworks possibles
        detected_frameworks = is_in_framework()
        if detected_frameworks:
            logging.info(f"Environnements détectés : {', '.join(detected_frameworks)}.")
        else:
            logging.warning("Aucun environnement de framework spécifique détecté.")
    
    # Si l'environnement Foundry est détecté ou spécifié
    if "foundry" in detected_frameworks or framework_arg == "foundry":
        if sol_file:
            # Vérifie si le fichier Solidity existe
            if os.path.isfile(sol_file):
                # Installation des imports avec la bibliothèque supplémentaire
                install_solidity_imports(sol_file, extra_lib)
                
                version = get_solidity_version(sol_file)
                if version:
                    logging.info(f"Version de Solidity pour {sol_file} : {version}")
                    if select_solc_version(version):
                        ast = generate_ast(sol_file)
                        if ast:
                            logging.info(f"AST générée pour {sol_file} avec succès.")
                            logging.debug(json.dumps(ast, indent=4))  # Détail de l'AST en debug
                            
                            # Génération du fichier de test
                            generate_fuzzing_test(ast, "FuzzContract")
                        else:
                            logging.error(f"Erreur : échec de la génération de l'AST pour {sol_file}.")
                    else:
                        logging.error(f"Erreur : impossible de sélectionner la version {version}.")
                else:
                    logging.error(f"Erreur : impossible de détecter la version de Solidity pour {sol_file}.")
            else:
                logging.error(f"Le fichier spécifié {sol_file} n'a pas été trouvé dans le répertoire Foundry.")
        else:
            # Si aucun fichier n'est spécifié, traite tous les fichiers Solidity dans Foundry
            sol_files = get_solidity_files_from_foundry()
            if sol_files:
                logging.info(f"Fichiers Solidity trouvés dans Foundry : {', '.join(sol_files)}")
                for sol_file in sol_files:
                    install_solidity_imports(sol_file, extra_lib)
                    
                    version = get_solidity_version(sol_file)
                    if version:
                        logging.info(f"Version de Solidity pour {sol_file} : {version}")
                        if select_solc_version(version):
                            ast = generate_ast(sol_file)
                            if ast:
                                logging.info(f"AST générée pour {sol_file} avec succès.")
                                logging.debug(json.dumps(ast, indent=4))  # Détail de l'AST en debug
                                
                                # Génération du fichier de test
                                generate_fuzzing_test(ast, "FuzzContract")
                            else:
                                logging.error(f"Erreur : échec de la génération de l'AST pour {sol_file}.")
                        else:
                            logging.error(f"Erreur : impossible de sélectionner la version {version}.")
                    else:
                        logging.error(f"Erreur : impossible de détecter la version de Solidity pour {sol_file}.")
            else:
                logging.error("Aucun fichier Solidity trouvé dans Foundry.")
        return
    
    # Si Foundry n'est pas utilisé, vérifier si solc est installé
    if not is_solc_installed():
        logging.error("Erreur : solc n'a pas pu être installé.")
        return
    
    # Obtenir la version de Solidity pour le fichier spécifié
    version = get_solidity_version(sol_file)
    if not version:
        logging.error("Erreur : impossible de détecter la version de Solidity.")
        return
    
    # Sélectionner la version correcte de solc
    if not select_solc_version(version):
        logging.error(f"Erreur : impossible de sélectionner la version {version}.")
        return
    
    # Générer l'AST pour le fichier spécifié
    ast = generate_ast(sol_file)
    if ast:
        logging.info("AST générée avec succès.")
        logging.debug(json.dumps(ast, indent=4))  # Détail de l'AST en debug
        
        # Génération du fichier de test
        generate_fuzzing_test(ast, "FuzzContract")
    else:
        logging.error("Erreur : échec de la génération de l'AST.")


if __name__ == "__main__":
    args = parser.parse_args()
    main(args.file, args.framework, args.lib)
