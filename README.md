# my-fuzzer
fuzzer pour les smart contract solidity a base de l'[ast](https://en.wikipedia.org/wiki/Abstract_syntax_tree)

![belier](./img/belier.png "belier")

## Fonctionnalités
- Vérification de l'installation de solc et installation automatique via solc-select.
- Détection des environnements Foundry et Hardhat.
- Génération de l'AST d'un fichier Solidity spécifique ou de tous les fichiers Solidity dans un projet Foundry.
- Sélection automatique de la version de Solidity basée sur les fichiers Solidity.

## TODO
- l'argument pour l'installation des import (--lib) a reparer. (ne prend pas bien l'arg et essayer d'installer tout le temps les imports)
- améliorer la fonction pour generer la gen de fuzz pour foundry

## 📁 File Structure
```bash
.
├── README.md
├── requirement.txt
└── src
    ├── main.py
    └── test
        ├── cache
        │   └── solidity-files-cache.json
        ├── foundry.toml
        ├── medusa.json
        ├── out
        ├── README.md
        ├── script
        │   └── Counter.s.sol
        ├── src
        │   └── Counter.sol
        └── test
            └── Counter.t.sol
```

## 🔒 License
Ce projet est sous licence [GNU General Public License v3.0](https://choosealicense.com/licenses/gpl-3.0/).
