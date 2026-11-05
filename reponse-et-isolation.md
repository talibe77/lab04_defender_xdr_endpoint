# Réponse à incident : décider, puis agir

## 1. Comment décider quoi faire : on ne s'improvise pas
On s'appuie sur deux choses, jamais sur le feeling :

- **Le cycle de réponse à incident** (NIST / SANS) :
  > Préparation → Détection & analyse → **Confinement** → Éradication → Récupération → Leçons apprises

  L'isolation = **confinement**, et elle vient **après** l'analyse, jamais avant.

- **Les playbooks** : chaque type d'incident (force brute, malware, hameçonnage…) a une procédure écrite. En Tier 1, on trie et on applique la procédure ; les décisions lourdes (isoler un serveur critique) sont validées par le Tier 2/3 ou l'équipe IR.

## 2. La question clé : ciblé ou compromis ?
| Situation | Compromis ? | Action |
|---|---|---|
| Force brute, **0 connexion réussie** (lab 1) | Non — *ciblé* | Bloquer les IP source, fermer/JIT le port, durcir. **On n'isole pas.** |
| Force brute **+ connexion réussie** + activité suspecte | Oui | **On isole.** |

Dans le lab 1 : 4 509 tentatives, **aucune réussie** → on n'isole pas, on bloque la source et on durcit. Isoler un poste sain perturbe un utilisateur pour rien. C'est un piège classique d'entrevue (« j'isole tout de suite » = mauvaise réponse).

**Trois questions avant d'isoler :**
1. Est-ce **confirmé compromis** (pas juste attaqué) ?
2. Quel est l'**impact métier** de l'isolation (serveur critique, base de production…) ?
3. Ai-je l'**autorisation** ?

## 3. Les actions de réponse de Defender for Endpoint
| Action | Effet |
|---|---|
| **Isolate device** | Coupe tout le réseau **sauf** la connexion à Defender (on garde le contrôle à distance) |
| Release from isolation | Remet la machine en ligne |
| Run antivirus scan | Analyse antivirus à distance |
| Collect investigation package | Rassemble les preuves (processus, connexions, journaux) |
| Restrict app execution | N'autorise que les applications signées |
| Stop and quarantine a file | Tue et met en quarantaine un fichier sur toutes les machines |

Toutes peuvent être **automatisées** (règle d'automatisation / playbook), par exemple isoler sur une alerte de gravité élevée.

## 4. Ce que j'ai testé
Cycle complet sur vm-honeypot :
1. **Isolate device** (Full isolation) avec commentaire « Test IR lab 4 » → statut *Device isolation configuration applied*, badge **Isolated** sur l'appareil.
2. **Release from isolation** avec commentaire → la machine revient en ligne.

Les deux actions apparaissent dans l'**Action center** (onglet History), en *Succeeded*, avec l'heure, l'appareil, l'auteur et la source (Portal). C'est la **piste d'audit** : en entreprise, on sait toujours qui a fait quoi, quand et pourquoi.

> ⚠️ Toujours **relâcher** l'appareil après un test : une VM laissée isolée reste coupée du réseau au prochain démarrage.
