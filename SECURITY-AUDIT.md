# Audit de sécurité — Rewindarr v5.12.0

- Code : tag `v5.12.0` (commit `e9c4acf`)
- Image : `ghcr.io/raunot/rewindarr:5.12.0@sha256:2b73b44a5f95829864f5d2573838f994b41e6573ad9362d5e0161d1c62f1853f`
- Date : 2026-11-11
- Méthode : revue manuelle des chemins sensibles (auth, middleware, routes API, server actions, proxy d'images, écritures disque, appels sortants, CI) + Trivy (image, lockfile, Dockerfile). Revue ciblée, pas exhaustive ligne à ligne.

## Verdict

Pas de code malveillant ni de backdoor trouvé. Le code est défensif (anti-SSRF, contrôle d'accès vérifié côté serveur, secrets en 0600). Les risques sont surtout de configuration.

## Constats

| # | Sévérité | Constat | Mitigation |
|---|----------|---------|------------|
| 1 | Haute (config) | Tant que `setupComplete` est faux, **n'importe qui, même non connecté**, peut ouvrir `/settings` et configurer l'app (URL/clé API Tautulli, admin). | Faire le setup initial via `kubectl port-forward` **avant** d'exposer l'Ingress / la route Cloudflare. |
| 2 | Moyenne (config) | `general.isOutsideAccess` rend dashboard, activité et historique visibles sans login (avec IP publiques, appareils, etc.). | Laisser désactivé. |
| 3 | Moyenne | `/api/*` est exclu du middleware : chaque route vérifie elle-même. Vérifié : `image` (allowlist stricte, pas de session par design), `rewind/*`, `status`, `health`, `missing-setting` (aucune donnée sensible). | Rien à faire ; un auth en amont réduirait cette surface. |
| 4 | Info | Login = Plex PIN (plex.tv) puis vérif d'appartenance au serveur via Tautulli ; revérification toutes les heures. Les droits admin viennent de Tautulli. | OK. |
| 5 | Info | Proxy d'images : allowlist d'hôtes, de chemins Plex (`/library/metadata/...`) et de paramètres ; redirections revérifiées à chaque saut ; 10 MiB max. Pas de SSRF trouvée. | OK. |
| 6 | Info | Appels sortants : plex.tv, api.github.com (vérif de version), TMDB, api.radarr.video, skyhook.sonarr.tv, Algolia (clé de recherche publique Rotten Tomatoes), tvthemes.plexapp.com. Google Analytics seulement si un admin met un ID. | OK ; tout est en HTTPS sur 443. |
| 7 | Info | Aucune utilisation de `eval`, `child_process`, `dangerouslySetInnerHTML`. Écritures disque limitées à `/app/config` et `.next/cache`. | Rootfs en lecture seule possible. |
| 8 | Info | CI : actions épinglées par SHA, permissions déclarées. Scripts de build autorisés limités (`allowBuilds`). | OK. |

## Image (Trivy)

- Dépendances de l'app (`pnpm-lock.yaml`) : **0 CVE**.
- Image : 6 HIGH / 13 MEDIUM / 1 LOW, toutes corrigeables, **toutes dans le CLI `npm` de l'image de base** (`/usr/local/lib/node_modules/npm` : undici, brace-expansion, glob, minimatch…) + `zlib` (alpine). npm n'est pas utilisé à l'exécution.
- Dockerfile : pas d'instruction `USER` (DS-0002) ; l'entrypoint démarre en root puis descend via `su-exec`. En Kubernetes on force `runAsUser: 1000`, l'entrypoint saute alors le chown.

Pour une image propre : rebuild du fork en supprimant npm/corepack/yarn du stage `runner` et avec `USER node`.

## Déploiement retenu (talos-kubernetes-lab)

`runAsNonRoot` 1000, `readOnlyRootFilesystem` (emptyDir sur `.next/cache` et `/tmp`), drop ALL, seccomp RuntimeDefault, pas de token SA, image épinglée par digest, egress limité (DNS, Internet 80/443, Tautulli, Plex).
