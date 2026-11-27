# Sicherheit

## Authentifizierung und Autorisierung
| Zugriff | Mechanismus | Prüfung |
|---|---|---|
| Dashboard (`/v1/events`, `/v1/alerts`) | Session-Cookie; das Microsoft-Token liegt serverseitig und wird bei **jedem** Aufruf neu validiert | Signatur, Aussteller, Audience, Ablauf, Scope `access_as_user`; danach Entra-App-Rolle `Admin` |
| Event-Eingang (`/v1/ingest`) | API-Key im Header `X-API-Key` | SHA-256-Hash, zeitkonstanter Vergleich, Status und Ablauf; Application und Environment stammen aus dem Key, nie aus dem Request |
| `/health`, `/api/auth/config` | öffentlich | enthalten keine Daten |

## Entscheidungen
- Token-Validierung bei jedem Endpunkt, aber das Token verlässt den Server nie (Backend-for-Frontend): kein Token im Browser-Speicher, daher kein Diebstahl durch eingeschleustes JavaScript.
- Rechte kommen aus Entra (App-Rolle `Admin`), nicht aus dem Code; keine eigene Benutzerverwaltung.
- Keine Secrets im Repo oder Image. Konfiguration per Umgebungsvariablen; DB-Zugang per Managed Identity.
- Audit-Events sind append-only (Rolle ohne UPDATE/DELETE plus Trigger).
- Container läuft als Nicht-Root-Nutzer.

## Bekannte Einschränkungen
- Sessions liegen im Arbeitsspeicher: eine Instanz, Neustart oder Deploy meldet alle ab.
- Ein entzogenes Recht gilt bis zum Ablauf des Microsoft-Tokens (ca. 1 Stunde).
- Ein Admin liest alle Applications; Rechte pro Application sind ein Ausblick.
- Der Logout beendet nur die App-Session, nicht die Microsoft-Anmeldung im Browser.
