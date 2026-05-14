# simple-port-scanner

Petit scanner de ports TCP en Python.

Le but est de faire un projet simple, lisible et facile a modifier pour apprendre les bases des sockets, de `argparse` et d'une sortie JSON.

## Fonctionnalites

- scan d'une seule cible
- scan de plusieurs cibles avec `--targets`
- ports sous forme de liste: `22,80,443`
- ports sous forme de plage: `1-1024`
- affiche les ports ouverts
- option verbose pour afficher aussi les ports fermes
- petite detection de service avec un dictionnaire
- tentative simple de recuperation de banniere
- affichage plus detaille dans le terminal
- sortie JSON possible
- aucune dependance externe

## Avertissement

Ce script doit etre utilise uniquement sur vos machines, dans un lab, ou avec une autorisation claire.

Ne scannez pas des machines qui ne vous appartiennent pas.

## Structure

```text
simple-port-scanner/
├── README.md
├── .gitignore
├── LICENSE
└── scanner.py
```

## Installation

Il faut seulement Python 3.11 ou plus.

```bash
cd simple-port-scanner
```

Aucune librairie a installer.

## Utilisation

![image](demofinal.gif)

```bash
python scanner.py --target scanme.nmap.org --ports 22,80,443
```

Options:

- `--target`: une seule cible a scanner
- `--targets`: plusieurs cibles separees par des virgules
- `--ports`: ports a scanner
- `--timeout`: timeout en secondes
- `--json`: sortie JSON
- `--verbose`: affiche aussi les ports fermes

## Exemples

Scanner 3 ports:

```bash
python scanner.py --target scanme.nmap.org --ports 22,80,443
```

Scanner plusieurs cibles:

```bash
python scanner.py --targets scanme.nmap.org,127.0.0.1 --ports 22,80,443
```

Scanner une plage:

```bash
python scanner.py --target 127.0.0.1 --ports 1-100
```

Afficher aussi les ports fermes:

```bash
python scanner.py --target 127.0.0.1 --ports 22,80,443 --verbose
```

Sortie JSON:

```bash
python scanner.py --target scanme.nmap.org --ports 22,80,443 --json
```

## Comment ca marche

Le script ouvre une connexion TCP sur chaque port avec `socket`.

Si la connexion marche, le port est considere comme ouvert.

Ensuite, le script essaie de lire une petite banniere. Pour HTTP, il envoie une requete `HEAD` tres simple.

Le nom du service vient d'abord d'un dictionnaire de ports connus, puis il peut etre ajuste avec la banniere.

Pour chaque cible, le script affiche aussi l'IP resolue, le nombre de ports testes, le timeout, le temps de reponse par port et un petit resume.

## Exemple de sortie texte

```text
=======================================================
Cible       : scanme.nmap.org
IP          : 45.33.32.156
Ports       : 3
Timeout     : 1.0s
=======================================================
---------------------------------------------
Port        : 22/tcp
Etat        : open
Service     : SSH
Temps       : 0.18s
Banniere    : SSH-2.0-OpenSSH
---------------------------------------------
Port        : 80/tcp
Etat        : open
Service     : HTTP
Temps       : 0.21s
Banniere    : HTTP/1.1 200 OK
---------------------------------------------
Resume
Ports ouverts : 2
Ports fermes  : 1
Duree scan    : 0.39s
```

## Exemple de sortie JSON

```json
{
  "targets": [
    {
      "target": "scanme.nmap.org",
      "ip": "45.33.32.156",
      "results": [
        {
          "port": 22,
          "state": "open",
          "service": "SSH",
          "banner": "SSH-2.0-OpenSSH",
          "response_time": 0.18
        }
      ],
      "open_ports": 1,
      "closed_ports": 2,
      "scan_time": 0.42
    }
  ]
}
```

## Limites

- pas de scan UDP
- pas de scan parallele
- pas de detection avancee
- pas de TLS pour les bannieres HTTPS
- scan des cibles une par une
- les resultats peuvent changer selon le pare-feu ou le reseau

## Idees d'amelioration

- ajouter du multi-thread
- lire une liste de cibles depuis un fichier
- ajouter une sortie CSV
- ajouter quelques tests

## Licence

MIT. Voir `LICENSE`.
