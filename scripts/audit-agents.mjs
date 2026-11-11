// Audit de sécurité des fichiers qui pilotent les agents IA (agents, skills, instructions,
// hooks, scripts, CI). Cherche les tentatives d'injection d'instructions et d'exécution de
// code cachées dans une pull request.
//
// Usage :
//   node scripts/audit-agents.mjs                         analyse complète de l'arbre de travail
//   node scripts/audit-agents.mjs --base <ref> [--head <ref>]
//                                                         analyse des changements base..head
//   Option --root <dossier> : dépôt à analyser (défaut : dossier courant).
//
// En mode diff, le contenu est lu dans git (`git show`), pas dans l'arbre de travail : on
// peut auditer une PR sans la récupérer dans son arbre de travail, donc sans qu'aucun de ses
// hooks ne s'exécute.
// Code de sortie : 1 s'il y a au moins une erreur, 0 sinon (les alertes ne bloquent pas).
import { readFileSync, appendFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { execFileSync } from "node:child_process";

// --- Classification des fichiers -------------------------------------------------------

// Fichiers lus par les agents comme des instructions, ou qui exécutent du code.
const SENSITIVE = [
  /^\.claude\//,
  /^\.github\//,
  /^\.githooks\//,
  /^\.husky\//,
  /^scripts\//,
  /^docs\/agents\//,
  /^docs\/design\//,
  /(^|\/)(CLAUDE|AGENTS)(\.local)?\.md$/,
  /^\.mcp\.json$/,
  /^\.vscode\/mcp\.json$/,
  /^package\.json$/,
];

// Toute modification de ces fichiers donne une alerte : ils exécutent du code ou
// contrôlent la revue.
const CHANGE_ALERTS = [
  [/^\.claude\/settings(\.local)?\.json$/, "configuration Claude Code (hooks, permissions)"],
  [/^\.claude\/hooks\//, "hook Claude Code"],
  [/^\.githooks\/|^\.husky\//, "hook git"],
  [/^scripts\//, "script lancé par les hooks ou la CI"],
  [/^\.github\/workflows\/|^\.github\/actions\//, "workflow CI"],
  [/^\.github\/CODEOWNERS$/, "règles de revue (CODEOWNERS)"],
  [/^\.mcp\.json$|^\.vscode\/mcp\.json$/, "serveurs MCP"],
  [/^package\.json$/, "scripts npm"],
];

// Nouveau fichier ici = nouvelle capacité donnée aux agents.
const NEW_CAPABILITY =
  /^\.claude\/(agents|commands|skills|output-styles|plugins)\/|^\.github\/(agents|prompts|instructions|chatmodes)\//;

const AGENT_FILE = /^(\.claude\/agents\/[^/]+\.md|\.github\/agents\/[^/]+\.agent\.md)$/;
const SETTINGS_FILE = /^\.claude\/settings(\.local)?\.json$/;

// Le scanner et ses tests contiennent les motifs qu'ils cherchent : on ne leur applique
// que la recherche de caractères invisibles.
const SELF = /^scripts\/audit-agents(\.test)?\.mjs$/;

const isSensitive = (f) => SENSITIVE.some((re) => re.test(f));
const changeAlert = (f) => CHANGE_ALERTS.find(([re]) => re.test(f))?.[1];

// --- Caractères invisibles ---------------------------------------------------------------

// Caractères qui ne s'affichent pas en revue mais que le modèle lit. Les espaces insécables
// (U+00A0, U+202F) de la typographie française ne sont pas concernés.
const INVISIBLE_RANGES = [
  [0x200b, 0x200c, "error", "espace ou liant de largeur nulle"],
  [0x200d, 0x200d, "warning", "liant de largeur nulle (emoji composé ?)"],
  [0x200e, 0x200f, "error", "marque de direction du texte"],
  [0x202a, 0x202e, "error", "contrôle bidirectionnel"],
  [0x2060, 0x2064, "error", "caractère de formatage invisible"],
  [0x2066, 0x2069, "error", "isolat bidirectionnel"],
  [0xfeff, 0xfeff, "error", "BOM au milieu du texte"],
  [0x00ad, 0x00ad, "warning", "trait d'union conditionnel"],
  [0x180e, 0x180e, "error", "séparateur de voyelles mongol"],
  [0xe0000, 0xe007f, "error", "caractère « tag » (texte caché)"],
  [0xe0100, 0xe01ef, "error", "sélecteur de variante (données cachées)"],
];

const hex = (cp) => `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;

/** Caractères invisibles d'une ligne : [{ col, cp, level, label }]. */
export function findInvisible(text, { allowBom = false } = {}) {
  const hits = [];
  let col = 0;
  for (const ch of text) {
    col++;
    const cp = ch.codePointAt(0);
    if (cp === 0xfeff && allowBom && col === 1) continue;
    const range = INVISIBLE_RANGES.find(([lo, hi]) => cp >= lo && cp <= hi);
    if (range) hits.push({ col, cp, level: range[2], label: range[3] });
  }
  return hits;
}

// --- Motifs suspects ----------------------------------------------------------------------

const PATTERNS = [
  [
    "error",
    /\b(ignore|disregard|forget|override)\b[^\n]{0,30}\b(previous|prior|above|earlier|all|system)\b[^\n]{0,20}\b(instructions?|rules|prompts?|guidelines)\b/i,
    "consigne de contournement des instructions",
  ],
  [
    "error",
    /\b(ignore|ignorez|oublie|oubliez|écrase|remplace)\s+(toutes\s+)?(les|tes|vos)\s+(instructions|consignes|règles)\b/i,
    "consigne de contournement des instructions",
  ],
  [
    "error",
    /\bne\s+(tiens|tenez)\s+(pas|plus)\s+compte\s+des\s+(instructions|consignes|règles)\b/i,
    "consigne de contournement des instructions",
  ],
  [
    "error",
    /\b(do not|don't|never)\s+(tell|inform|mention|reveal|show|notify)\b[^\n]{0,30}\buser\b/i,
    "consigne de dissimulation à l'utilisateur",
  ],
  [
    "error",
    /\bne\s+(le\s+|lui\s+|rien\s+)?(dis|dites|mentionne|mentionnez|signale|signalez|révèle|révélez|montre|montrez)\s+(pas|rien|jamais)\b[^\n]{0,30}\butilisateur/i,
    "consigne de dissimulation à l'utilisateur",
  ],
  [
    "error",
    /\bsans\s+(le\s+)?(dire|prévenir|informer|signaler|avertir)\b[^\n]{0,20}\butilisateur/i,
    "consigne de dissimulation à l'utilisateur",
  ],
  ["error", /\b(curl|wget)\b[^\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/i, "téléchargement exécuté directement"],
  [
    "error",
    /\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]*\|\s*(iex|Invoke-Expression)\b/i,
    "téléchargement exécuté directement",
  ],
  ["error", /\bbase64\s+(-d|--decode)\b[^\n]*\|\s*(ba|z)?sh\b/i, "commande encodée exécutée"],
  ["error", /--dangerously-skip-permissions|\bbypassPermissions\b/, "contournement des permissions"],
  [
    "error",
    /\b(webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app)|interactsh|burpcollaborator|oast\.(fun|pro|live|site))\b/i,
    "domaine d'exfiltration connu",
  ],
  ["warning", /--no-verify\b|--no-gpg-sign\b/, "contournement des hooks git"],
  ["warning", /\bgit\s+push\b[^\n]*(--force\b|\s-f\b)/, "push forcé"],
  [
    "warning",
    /\b(ANTHROPIC_API_KEY|OPENAI_API_KEY|GITHUB_TOKEN|GH_TOKEN|AWS_SECRET_ACCESS_KEY|NPM_TOKEN)\b|\.ssh\/|\bid_(rsa|ed25519)\b/,
    "mention d'un secret",
  ],
  ["warning", /[A-Za-z0-9+/]{120,}={0,2}/, "long bloc encodé"],
];

// Seulement sur les lignes ajoutées (mode diff) : trop de bruit sur un fichier entier.
const DIFF_ONLY_PATTERNS = [["warning", /https?:\/\/[^\s)>"'`]+/, "URL externe ajoutée"]];

// Commentaire HTML : invisible une fois le Markdown rendu, mais lu par le modèle.
const HTML_COMMENT = /<!--/;

// Retire tout ce qui pourrait casser la sortie ou injecter une commande de workflow GitHub
// (retour à la ligne, caractères de contrôle ou invisibles) et tronque.
export function snippet(s, max = 80) {
  const clean = [...s]
    .map((ch) => {
      const cp = ch.codePointAt(0);
      if (cp < 0x20 || cp === 0x7f || findInvisible(ch).length) return " ";
      return ch;
    })
    .join("")
    .trim();
  return clean.length > max ? `${clean.slice(0, max)}…` : clean;
}

// --- Analyse de lignes ------------------------------------------------------------------

/**
 * @param {string} file chemin relatif au dépôt
 * @param {{ n: number, text: string }[]} lines lignes à analyser
 * @param {{ diff?: boolean }} opts diff = lignes ajoutées seulement
 */
export function scanLines(file, lines, { diff = false } = {}) {
  const findings = [];
  const patterns = isSensitive(file) && !SELF.test(file);
  const md = file.endsWith(".md");
  for (const { n, text } of lines) {
    for (const h of findInvisible(text, { allowBom: n === 1 }))
      findings.push({ level: h.level, file, line: n, message: `caractère invisible ${hex(h.cp)} (${h.label}), colonne ${h.col}` });
    if (!patterns) continue;
    for (const [level, re, label] of diff ? [...PATTERNS, ...DIFF_ONLY_PATTERNS] : PATTERNS) {
      const m = text.match(re);
      if (m) findings.push({ level, file, line: n, message: `${label} : « ${snippet(m[0])} »` });
    }
    if (md && HTML_COMMENT.test(text))
      findings.push({ level: "warning", file, line: n, message: "commentaire HTML (invisible une fois le Markdown rendu)" });
  }
  return findings;
}

/** Lignes ajoutées d'un `git diff -U0` : [{ n, text }]. */
export function parseAddedLines(diff) {
  const out = [];
  let n = 0;
  for (const line of diff.replace(/\r\n/g, "\n").split("\n")) {
    const hunk = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunk) n = Number(hunk[1]);
    else if (line.startsWith("+++") || line.startsWith("---")) continue;
    else if (line.startsWith("+")) out.push({ n: n++, text: line.slice(1) });
  }
  return out;
}

const toLines = (text) => text.replace(/\r\n/g, "\n").split("\n").map((t, i) => ({ n: i + 1, text: t }));

// --- Frontmatter des agents ---------------------------------------------------------------

/** Clés de premier niveau du frontmatter YAML : { clé: valeur brute } ou null. */
export function parseFrontmatter(text) {
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  if (lines[0].replace(/^\uFEFF/, "") !== "---") return null;
  const fm = {};
  let key = null;
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (line === "---") return fm;
    const m = line.match(/^([A-Za-z][\w-]*):\s*(.*)$/);
    if (m) {
      key = m[1];
      fm[key] = m[2];
    } else if (key) fm[key] += `\n${line}`;
  }
  return null;
}

const parseList = (v) =>
  v === undefined
    ? null
    : v
        .replace(/[[\]"']/g, "")
        .split(/[,\n]/)
        .map((t) => t.replace(/^\s*-\s*/, "").trim())
        .filter(Boolean);
const scalar = (v) => (v ?? "").trim().replace(/^["']|["']$/g, "");
const lineOf = (text, key) => {
  const i = text.replace(/\r\n/g, "\n").split("\n").findIndex((l) => l.startsWith(`${key}:`));
  return i >= 0 ? i + 1 : 1;
};

/**
 * @param {string} file
 * @param {string | null | undefined} baseText undefined = analyse complète, null = nouveau fichier
 * @param {string} headText
 */
export function agentFindings(file, baseText, headText) {
  const findings = [];
  const add = (level, key, message) => findings.push({ level, file, line: lineOf(headText, key), message });
  const head = parseFrontmatter(headText);
  if (!head) return [{ level: "warning", file, line: 1, message: "frontmatter absent ou illisible" }];
  const base = baseText ? parseFrontmatter(baseText) : null;

  if (baseText === null) add("warning", "name", "nouvel agent : relire ses outils et ses instructions");
  if (head.tools === undefined) add("warning", "name", "aucune ligne tools: l'agent hérite de tous les outils");
  if (scalar(head.permissionMode) === "bypassPermissions")
    add("error", "permissionMode", "permissionMode: bypassPermissions (aucune demande de permission)");

  if (base) {
    const before = new Set(parseList(base.tools) ?? []);
    const added = (parseList(head.tools) ?? []).filter((t) => !before.has(t));
    if (added.length) add("warning", "tools", `outils ajoutés : ${added.join(", ")}`);
    if (base.tools !== undefined && head.tools === undefined)
      add("warning", "name", "ligne tools: supprimée : l'agent hérite désormais de tous les outils");
    if (scalar(base.model) !== scalar(head.model))
      add("warning", "model", `modèle modifié : ${scalar(base.model) || "(aucun)"} -> ${scalar(head.model) || "(aucun)"}`);
    if (scalar(base.permissionMode) !== scalar(head.permissionMode) && scalar(head.permissionMode) !== "bypassPermissions")
      add("warning", "permissionMode", `permissionMode modifié : ${snippet(scalar(head.permissionMode)) || "(aucun)"}`);
  }
  for (const key of ["hooks", "mcpServers", "skills"]) {
    if (head[key] === undefined || (base && base[key] === head[key])) continue;
    add("warning", key, `${key} ${base && base[key] !== undefined ? "modifié" : "présent"} dans le frontmatter`);
  }
  return findings;
}

// --- Configuration Claude Code ------------------------------------------------------------

const BROAD_BASH = /^Bash(\(\s*(\*|:\*)?\s*\))?$/;
// Clés dont la valeur est une commande exécutée par Claude Code.
const EXEC_KEYS = new Set(["hooks", "statusLine", "apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper"]);

function commands(node, out = new Set()) {
  if (Array.isArray(node)) node.forEach((n) => commands(n, out));
  else if (node && typeof node === "object")
    for (const [k, v] of Object.entries(node)) {
      if (k === "command" && typeof v === "string") out.add(v);
      else commands(v, out);
    }
  return out;
}

/** Même convention que agentFindings pour baseText. */
export function settingsFindings(file, baseText, headText) {
  let head;
  try {
    head = JSON.parse(headText);
  } catch {
    return [{ level: "error", file, line: 1, message: "JSON invalide" }];
  }
  let base = null;
  if (baseText) {
    try {
      base = JSON.parse(baseText);
    } catch {
      base = {};
    }
  }
  const findings = [];
  const add = (level, message) => findings.push({ level, file, line: 1, message });

  for (const rule of head.permissions?.allow ?? [])
    if (typeof rule === "string" && BROAD_BASH.test(rule.trim())) add("error", `permission trop large : ${snippet(rule)}`);
  if (head.permissions?.defaultMode === "bypassPermissions")
    add("error", "permissions.defaultMode: bypassPermissions (aucune demande de permission)");
  if (head.enableAllProjectMcpServers === true) add("warning", "enableAllProjectMcpServers: tous les serveurs MCP du projet sont activés");

  if (baseText === undefined) return findings;
  const old = base ?? {};
  for (const key of new Set([...Object.keys(old), ...Object.keys(head)])) {
    if (JSON.stringify(old[key]) === JSON.stringify(head[key])) continue;
    add("warning", `clé « ${snippet(key)} » modifiée${EXEC_KEYS.has(key) ? " (exécute des commandes)" : ""}`);
  }
  const before = commands(old);
  for (const cmd of commands(head)) if (!before.has(cmd)) add("warning", `nouvelle commande exécutée : « ${snippet(cmd)} »`);
  const allowed = new Set(old.permissions?.allow ?? []);
  for (const rule of head.permissions?.allow ?? [])
    if (!allowed.has(rule)) add("warning", `nouvelle permission accordée : ${snippet(String(rule))}`);
  return findings;
}

// --- Accès git ------------------------------------------------------------------------------

const git = (root, args) =>
  execFileSync("git", ["-C", root, ...args], { encoding: "buffer", maxBuffer: 64 * 1024 * 1024 });

const isBinary = (buf) => buf.includes(0);

function show(root, ref, file) {
  try {
    const buf = git(root, ["show", `${ref}:${file}`]);
    return isBinary(buf) ? null : buf.toString("utf8");
  } catch {
    return null;
  }
}

// --- Audit ----------------------------------------------------------------------------------

function contentFindings(file, baseText, headText) {
  if (AGENT_FILE.test(file)) return agentFindings(file, baseText, headText);
  if (SETTINGS_FILE.test(file)) return settingsFindings(file, baseText, headText);
  return [];
}

/** Analyse complète de l'arbre de travail (fichiers suivis par git). */
export function auditTree(root) {
  const files = git(root, ["ls-files", "-z"]).toString("utf8").split("\0").filter(Boolean);
  const findings = [];
  for (const file of files) {
    let buf;
    try {
      buf = readFileSync(join(root, file));
    } catch {
      continue; // supprimé de l'arbre de travail
    }
    if (isBinary(buf)) continue;
    const text = buf.toString("utf8");
    findings.push(...scanLines(file, toLines(text)), ...contentFindings(file, undefined, text));
  }
  return findings;
}

/** Analyse des changements entre deux révisions, lus dans git. */
export function auditDiff(root, base, head = "HEAD") {
  const status = git(root, ["diff", "--name-status", "--no-renames", "-z", base, head]).toString("utf8").split("\0");
  const findings = [];
  for (let i = 0; i + 1 < status.length; i += 2) {
    const [code, file] = [status[i], status[i + 1]];
    const alert = changeAlert(file);
    if (code === "D") {
      if (alert || isSensitive(file)) findings.push({ level: "warning", file, message: `fichier supprimé${alert ? ` (${alert})` : ""}` });
      continue;
    }
    if (alert) findings.push({ level: "warning", file, message: `${alert} : ${code === "A" ? "ajouté" : "modifié"}, à relire` });
    if (code === "A" && NEW_CAPABILITY.test(file) && !AGENT_FILE.test(file))
      findings.push({ level: "warning", file, message: "nouvelle capacité (skill, commande, prompt) : à relire" });

    const headText = show(root, head, file);
    if (headText === null) continue; // binaire
    const added = parseAddedLines(git(root, ["diff", "-U0", "--no-renames", base, head, "--", file]).toString("utf8"));
    findings.push(...scanLines(file, added, { diff: true }));
    findings.push(...contentFindings(file, code === "A" ? null : show(root, base, file) ?? "", headText));
  }
  return findings;
}

// --- Rapport --------------------------------------------------------------------------------

const LABEL = { error: "ERREUR", warning: "ALERTE" };
const escData = (s) => s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
const escProp = (s) => escData(s).replace(/:/g, "%3A").replace(/,/g, "%2C");
const escCell = (s) => s.replace(/\|/g, "\\|").replace(/`/g, "'");

export function report(findings, env = process.env, out = console) {
  const sorted = [...findings].sort((a, b) => (a.level === b.level ? 0 : a.level === "error" ? -1 : 1));
  for (const f of sorted) {
    const where = `${snippet(f.file, 200)}${f.line ? `:${f.line}` : ""}`;
    out.log(`${LABEL[f.level]}  ${where}  ${f.message}`);
    if (env.GITHUB_ACTIONS === "true")
      out.log(`::${f.level} file=${escProp(f.file)}${f.line ? `,line=${f.line}` : ""}::${escData(f.message)}`);
  }
  const errors = findings.filter((f) => f.level === "error").length;
  const warnings = findings.length - errors;
  out.log(`\n${errors} erreur(s), ${warnings} alerte(s).`);
  if (env.GITHUB_STEP_SUMMARY) {
    const rows = sorted.map((f) => `| ${LABEL[f.level]} | \`${escCell(f.file)}${f.line ? `:${f.line}` : ""}\` | ${escCell(f.message)} |`);
    const body = findings.length
      ? ["| Niveau | Fichier | Constat |", "|---|---|---|", ...rows].join("\n")
      : "Aucun constat.";
    appendFileSync(env.GITHUB_STEP_SUMMARY, `## Audit de sécurité des agents\n\n${errors} erreur(s), ${warnings} alerte(s).\n\n${body}\n`);
  }
  return errors;
}

function arg(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

function main() {
  const root = resolve(arg("--root") ?? process.cwd());
  const base = arg("--base");
  const findings = base ? auditDiff(root, base, arg("--head") ?? "HEAD") : auditTree(root);
  process.exit(report(findings) ? 1 : 0);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main();
