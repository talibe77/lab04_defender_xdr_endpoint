# Chasse KQL et règle de détection personnalisée

## Le scénario
Un attaquant qui vient d'obtenir un accès lance plusieurs commandes de **reconnaissance** (tactique MITRE **Discovery**) pour cartographier la machine. Prises une par une, ces commandes sont trop courantes pour alerter ; en **rafale**, elles sont un signal.

Reconnaissance simulée en RDP :
```
whoami /all · systeminfo · net user · net localgroup administrators · ipconfig /all · netstat -ano · tasklist
```

## Chasse : voir la télémétrie
```kql
DeviceProcessEvents
| where DeviceName startswith "vm-honeypot"
| where Timestamp > ago(1h)
| where FileName in~ ("whoami.exe","systeminfo.exe","net.exe","net1.exe","ipconfig.exe","netstat.exe","tasklist.exe")
| project Timestamp, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp asc
```

**Observation (bonne question d'entrevue) :** 7 commandes → **9 lignes**. Chaque `net.exe` lance un enfant `net1.exe` (Windows délègue le travail). Connaître ces relations parent-enfant évite de croire à une activité anormale.

## Le piège de la règle : Timestamp + ReportId
Une règle de détection personnalisée doit retourner, pour chaque résultat, les colonnes **`Timestamp`** et **`ReportId`** (pour savoir *quand* et *sur quel événement* réagir). Or `summarize` les supprime.

**Solution :** compter les rafales dans un `let`, puis revenir aux événements individuels avec un `join`.

```kql
let fenetre = 10m;
let seuil = 4;
let decouverte = dynamic(["whoami.exe","systeminfo.exe","net.exe","net1.exe","ipconfig.exe","netstat.exe","tasklist.exe","nltest.exe","arp.exe","route.exe"]);
let rafales = DeviceProcessEvents
    | where FileName in~ (decouverte)
    | summarize CommandesDistinctes = dcount(FileName) by DeviceId, Fenetre = bin(Timestamp, fenetre)
    | where CommandesDistinctes >= seuil;
DeviceProcessEvents
| where FileName in~ (decouverte)
| extend Fenetre = bin(Timestamp, fenetre)
| join kind=inner rafales on DeviceId, Fenetre
| project Timestamp, ReportId, DeviceId, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

## La règle (Create detection rule)
| Paramètre | Valeur |
|---|---|
| Nom | Rafale de commandes de reconnaissance (Discovery) |
| Fréquence | Toutes les heures (doit être ≤ lookback) |
| Lookback | 1 heure |
| Gravité | Medium |
| MITRE | T1087 (Account Discovery), T1082 (System Information Discovery) |
| Entité | Device → DeviceId |

**Piège de l'assistant :** la fréquence doit être **inférieure ou égale** à la période de rétro-analyse (lookback). 3 h de fréquence avec 1 h de lookback raterait 2 h de données → ramené à « toutes les heures ».

## Résultat
La règle a généré **automatiquement un cas** (ID 15) regroupant les **9 alertes** de la reconnaissance, mappées sur l'appareil. Classé *Benign Positive – Security Testing* (test volontaire).

C'est la boucle complète d'un **ingénieur de détection** : simuler une technique → la chasser en KQL → en faire une règle → la voir détecter et générer un cas.
