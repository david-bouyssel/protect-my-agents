# protect-my-agents

Audit de sécurité des fichiers d'agents (définitions d'agents, `CLAUDE.md`, `AGENTS.md`,
skills, hooks, scripts, CI), repris de `poc-orchestration`.

Prérequis : Node 22 et `git`. Aucune dépendance npm.

## Sécurité des agents

Les agents obéissent à des fichiers texte : définitions d'agents, `CLAUDE.md`,
`AGENTS.md`, instructions Copilot, skills. Une pull request peut y glisser des
instructions malveillantes. Elle peut aussi modifier un hook ou un script qui s'exécute
sur ta machine. Trois protections s'ajoutent à ta relecture.

### Audit automatique des PR

Le workflow `.github/workflows/audit-agents.yml` lance `scripts/audit-agents.mjs` sur
chaque PR. Il ne relit que les lignes ajoutées.

| Niveau | Constat |
|---|---|
| **Erreur** (job en échec) | Caractère invisible ou bidirectionnel (texte caché au relecteur mais lu par le modèle) ; consigne de contournement des instructions ou de dissimulation à l'utilisateur ; téléchargement exécuté directement ; contournement des permissions ; domaine d'exfiltration connu ; permission `Bash` sans restriction |
| **Alerte** (annotation dans la PR) | Outil ajouté à un agent, ligne `tools:` retirée, modèle changé ; nouvel agent, skill, commande ou prompt ; hook, script, workflow, `CODEOWNERS` ou configuration MCP modifié ; nouvelle commande de hook ou nouvelle permission ; URL externe, commentaire HTML, mention de secret, long bloc encodé |

En PR, le scanner est lu sur la branche cible et non dans la PR : une PR ne peut pas
l'affaiblir pour se valider elle-même. Sur `main`, le workflow analyse tout le dépôt.

Le scanner cherche des motifs connus. Il ne remplace pas la relecture : une
consigne malveillante bien formulée passe au travers. Il sert à rendre visible ce qui
ne l'est pas et à pointer les fichiers à relire en priorité.

### Revue obligatoire : `CODEOWNERS`

`.github/CODEOWNERS` rend ta revue obligatoire pour les fichiers des agents, les hooks,
les scripts et la CI. **Le fichier est livré vide** : le compte responsable doit être
écrit en dur dans chaque règle, par toi, avant tout usage. Tant qu'il est vide, aucune
revue n'est imposée.

Remplis-le avec ton compte GitHub (ou une équipe `@org/equipe`), un chemin par ligne :

```text
/.claude/               @ton-compte
/.github/               @ton-compte
/.githooks/             @ton-compte
/scripts/               @ton-compte
/docs/agents/           @ton-compte
/.mcp.json              @ton-compte
/package.json           @ton-compte
CLAUDE.md               @ton-compte
CLAUDE.local.md         @ton-compte
AGENTS.md               @ton-compte
```

Pour que ce soit effectif, active une règle de protection sur
`main` (*Settings > Rules > Rulesets* ou *Settings > Branches*) :

- *Require a pull request before merging*, avec *Require review from Code Owners* ;
- *Dismiss stale pull request approvals when new commits are pushed*, pour qu'un commit
  ajouté après ton approbation demande une nouvelle revue ;
- *Require status checks to pass*, avec le job `audit`.

GitHub ne permet pas d'approuver sa propre PR. Si tu es seul sur le dépôt, garde le
contournement réservé aux administrateurs pour merger tes propres PR.

### Auditer une PR avant de la récupérer

Récupérer la branche d'une PR puis y lancer Claude Code peut exécuter ses hooks
(`.claude/settings.json`) et ses scripts. Audite-la d'abord, sans toucher à ton arbre
de travail :

```bash
git fetch origin pull/<numéro>/head:pr-<numéro>
```

```bash
node scripts/audit-agents.mjs --base main --head pr-<numéro>
```

Le scanner lit alors le contenu dans git, pas dans l'arbre de travail : rien de la PR ne
s'exécute. Relis ensuite le diff de `.claude/settings.json` et de `scripts/` avant de
récupérer la branche dans ton arbre de travail.

## Contenu du dépôt

| Chemin | Rôle |
|---|---|
| `scripts/audit-agents.mjs` | Audit de sécurité des fichiers des agents (tests : `node --test "scripts/*.test.mjs"`) |
| `.github/workflows/audit-agents.yml` | CI : audit de sécurité de chaque PR et tests du scanner |
| `.github/CODEOWNERS` | Vide : à remplir avec ton compte (section « Revue obligatoire ») |

## Mise en place

Écrire en dur ton compte dans `.github/CODEOWNERS`, qui est vide, puis activer la
protection de branche (section « Revue obligatoire »).
