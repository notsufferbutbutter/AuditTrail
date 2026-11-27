# Datenbank (Azure Database for PostgreSQL)

## Was umgesetzt ist

| Datei | Inhalt |
|---|---|
| `backend/migrations/001_initial_schema.sql` | Tabellen `applications`, `services`, `api_keys`, `audit_events`, `alerts`, `analysis_state`, Indizes, Append-only-Trigger, Rolle `audittrail_app` |
| `backend/migrate.py` | Führt Migrationen versioniert und genau einmal aus (`schema_migrations`, Advisory Lock) |
| `backend/db.py` | Verbindung: lokal per `DATABASE_URL`, in Azure per Managed Identity (kein Passwort), TLS-Pflicht für entfernte Server |
| `backend/repositories.py` | API-Key prüfen/anlegen/widerrufen, Events einfügen/lesen/listen, Alerts upsert/lesen/listen |
| `backend/test/test_database.py` | Tests gegen echtes PostgreSQL |

## Sicherheitsmaßnahmen (was tatsächlich gilt)

1. **Keine Secrets im Repo.** Lokal steht die Verbindung in `.env` (in `.gitignore`). In Azure gibt es kein DB-Passwort: Die Container App meldet sich mit ihrer Managed Identity über ein kurzlebiges Entra-Token an.
2. **TLS.** `db.py` verweigert Verbindungen zu nicht-lokalen Servern ohne `sslmode=require` (oder strenger). Azure erzwingt TLS zusätzlich serverseitig.
3. **Netzwerk.** Server nur aus der Container App und von freigegebenen Entwickler-IPs erreichbar (siehe unten).
4. **API-Keys nur als Hash.** Gespeichert wird `SHA-256(secret)`. Das Secret hat 256 Bit Zufall und wird nur einmal bei der Erstellung angezeigt. Der Vergleich ist zeitkonstant (`hmac.compare_digest`), unbekannte Key-IDs kosten dieselbe Arbeit. Widerrufene und abgelaufene Keys werden abgelehnt.
5. **Scope aus dem Key.** Application und Environment eines Events kommen aus dem geprüften Key, nie aus dem Request-Body. Alle Lesezugriffe filtern auf `(application_id, environment)`. Ein zusammengesetzter Fremdschlüssel verhindert, dass ein Event einen Service einer fremden Application angibt.
6. **Append-only, zwei Schichten.**
   * Die App-Rolle `audittrail_app` hat auf `audit_events` nur `SELECT` und `INSERT`.
   * Ein Trigger lehnt `UPDATE`, `DELETE` und `TRUNCATE` ab, auch für den Besitzer.
7. **Parametrisierte SQL-Abfragen** überall, damit keine SQL-Injection möglich ist.
8. **Idempotenz.** `UNIQUE (application_id, environment, event_id)`: Ein Retry speichert ein Event nicht doppelt.

**Grenzen (ehrlich dokumentiert):** Die Datenbank ist dadurch *nicht absolut* manipulationssicher. Ein Server-Admin bzw. der Tabellenbesitzer kann den Trigger deaktivieren, und ein Azure-Admin kann den Server löschen oder ein Backup zurückspielen. Gegen diese Fälle helfen nur zusätzliche Maßnahmen (Export in Blob Storage mit Immutable Policy, Hash-Kette, getrennte Admin-Rechte, Azure Activity Log). Sie sind im Zielbild vorgesehen, aber nicht Teil dieses Schritts.

**Hinweis zur Aufgabe "Nutzer kann Daten löschen":** Audit-Events sind bewusst nicht löschbar. Löschen bezieht sich bei uns auf Verwaltungsdaten (z. B. API-Key widerrufen). Das mit dem Professor abstimmen.

## Lokale Entwicklung

```bash
cp .env.example .env          # eigenes POSTGRES_PASSWORD eintragen
docker compose up -d db
python -m backend.migrate     # liest DATABASE_URL aus der Umgebung
```

Tests (eigene Wegwerf-Datenbank, nie gegen Produktion):

```bash
TEST_DATABASE_URL=postgresql://audittrail:<passwort>@localhost:5432/postgres pytest backend/test
```

## Azure einrichten (einmalig)

1. **Server anlegen:** Azure Database for PostgreSQL – Flexible Server, Ressourcengruppe `audittrail-rg`, Region Germany West Central, Burstable B1ms, Version 16.
   * **Authentifizierung: "Microsoft Entra authentication only"** (kein Passwort-Login). Dich selbst bzw. die Gruppe `audittrail-team` als Entra-Admin eintragen.
   * **Netzwerk:** Public access, *keine* Regel "Allow all Azure services". Nur die ausgehenden IPs der Container App (Container App, dann Eigenschaften, dann "Outbound IP addresses") und bei Bedarf die eigene IP freigeben. Besser, wenn Zeit bleibt: VNet-Integration bzw. Private Endpoint.
   * Serverparameter `require_secure_transport` bleibt `ON`.
2. **Datenbank `audittrail` anlegen.**
3. **Migration ausführen** (als Entra-Admin, mit Token als Passwort):
   ```bash
   export PGHOST=<server>.postgres.database.azure.com PGDATABASE=audittrail PGUSER=<deine E-Mail> PGSSLMODE=require
   export PGPASSWORD=$(az account get-access-token --resource-type oss-rdbms --query accessToken -o tsv)
   DATABASE_URL="host=$PGHOST dbname=$PGDATABASE user=$PGUSER sslmode=require" python -m backend.migrate
   ```
4. **App-Login anlegen** (in der Datenbank `postgres` bzw. `audittrail`, als Entra-Admin):
   ```sql
   SELECT * FROM pgaadauth_create_principal('audittrail-api', false, false);  -- Name der Managed Identity
   GRANT audittrail_app TO "audittrail-api";
   ```
   Die App bekommt so nur die Rechte der Rolle `audittrail_app`, kein Admin.
5. **Container App** (Umgebungsvariablen, keine Secrets):
   `DB_AUTH=managed-identity`, `PGHOST=<server>.postgres.database.azure.com`, `PGDATABASE=audittrail`, `PGUSER=audittrail-api`, `PGSSLMODE=require`.
   Bei einer benutzerzugewiesenen Identität zusätzlich `AZURE_CLIENT_ID=<client id>`.

6. Zusätlich:
Region North Europe statt Germany West Central. Begründung: Kapazitätsmangel in Belgium Central, Einschränkung des Testabos in Germany West Central.

Login-Name audittrail-api-mi, angelegt mit pgaadauth_create_principal_with_oid(...) über die Objekt-ID. Begründung: Der Name audittrail-api war doppelt vergeben.

Netzwerk: "Zugriff aus Azure-Diensten erlaubt, weil Container Apps (Consumption) keine festen ausgehenden IPs hat. Zielbild: VNet und Private Endpoint."
