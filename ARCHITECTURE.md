1. High-Level Architecture

This is the official system structure of SIEM-Lite:

+------------------------+
|    Linux Machines      |
| (agent installed here) |
+------------------------+
            |
            | JSON over HTTPS
            v
+------------------------+
|      Django API        |
| - JWT for agents       |
| - Machine registry     |
| - Log ingestion        |
+------------------------+
            |
            v
+------------------------+
|   Log Normalization    |
| - Parse fields         |
| - Enrich metadata      |
| - Map to LogEntry      |
+------------------------+
            |
            v
+------------------------+
|    Rule Engine         |
| - SSH brute force      |
| - Port scanning        |
| - Sudo misuse          |
| - File integrity       |
+------------------------+
            |
            v
+------------------------+
|    Alert Engine        |
| - Dedup / severity     |
| - Escalation           |
| - Email / Telegram     |
+------------------------+
            |
            v
+------------------------+
| Dashboard + Reports    |
| - Machines             |
| - Logs & alerts        |
| - Daily PDFs           |
+------------------------+


This is the blueprint we will implement across the next days.

2. Log Flow Pipeline (Detailed)

Here is the precise step-by-step lifecycle of every event SIEM-Lite will process:

Step 1 — Raw log originates on a Linux machine

Example log lines:

Failed password for invalid user admin from 192.168.1.5 port 48211 ssh2
Accepted password for ubuntu from 8.8.8.8 port 49995 ssh2
sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/cat /etc/shadow

Step 2 — Agent collects and normalizes

The agent will:

Tail specific files (auth.log, syslog)

Parse relevant patterns

Convert to JSON:

{
  "timestamp": "2025-02-12T18:10:44Z",
  "machine_id": "pi-exam-01",
  "event_type": "ssh_failed_login",
  "raw": "Failed password for invalid user admin...",
  "source_ip": "192.168.1.5",
  "username": "admin"
}

Step 3 — Agent sends data to Django ingestion endpoint
POST /api/logs/ingest/
Authorization: Bearer <TOKEN>
Content-Type: application/json

Step 4 — Django normalizes & stores

Inside the ingestion view:

Validate payload

Map to LogEntry

Save in PostgreSQL

Step 5 — Feed into the Rule Engine

Rule engine sees log events and checks:

Count events in a 5-minute sliding window

Match patterns against rules

Example: 5 failed SSH attempts → create alert

Step 6 — Alert Engine logic

Deduplicate identical alerts:

Same machine

Same type

Same IP

Within 10 minutes window

Then escalate if needed:

Level 1 → store alert

Level 2 → send email/Telegram

Step 7 — Dashboard UI

Admins use UI to:

Inspect logs

Review alerts

Check machine heartbeat

Download reports

3. Entity Relationship Diagram (ERD)

This is the official model structure you will implement on Day 3.

+------------------+
|     Machine      |
+------------------+
| id (UUID)        |
| name             |
| ip_address        |
| last_seen        |
| registered_at     |
| api_key (JWT)     |
+------------------+
        |
        | 1:N
        v
+------------------+
|    LogEntry      |
+------------------+
| id               |
| machine_id (FK)  |
| timestamp        |
| event_type       |
| raw_message      |
| source_ip        |
| username         |
| metadata (JSON)  |
+------------------+
        |
        | 1:N
        v
+------------------+
|      Alert       |
+------------------+
| id               |
| machine_id (FK)  |
| rule_id (FK)     |
| first_seen       |
| last_seen        |
| severity         |
| status           |
| message          |
+------------------+
        |
        | N:1
        v
+------------------+
|      Rule        |
+------------------+
| id               |
| name             |
| description      |
| threshold        |
| window_minutes   |
| event_type       |
| severity         |
+------------------+


Later we extend with FileIntegrityEvent and NetworkEvent.

4. API Contracts

These define how the frontend, agents, and backend communicate.

4.1 Machine Registration API
POST /api/machines/register/


Body:

{
  "machine_name": "ubuntu-server-01",
  "ip_address": "192.168.0.10"
}


Response:

{
  "machine_id": "42cb...e9f3",
  "token": "<JWT>"
}

4.2 Log Ingestion API
POST /api/logs/ingest/
Authorization: Bearer <JWT>


Body:

{
  "timestamp": "2025-02-12T18:10:44Z",
  "event_type": "ssh_failed_login",
  "raw_message": "Failed password for invalid user admin...",
  "source_ip": "192.168.1.5",
  "username": "admin",
  "metadata": {
    "port": "48211"
  }
}

4.3 Rules API

Admin only.

GET /api/rules/
POST /api/rules/
PUT /api/rules/<id>/
DELETE /api/rules/<id>/


Rule example:

{
  "name": "SSH brute-force",
  "event_type": "ssh_failed_login",
  "threshold": 5,
  "window_minutes": 3,
  "severity": "high"
}

4.4 Alerts API
GET /api/alerts/
GET /api/alerts/<id>/
PATCH /api/alerts/<id>/resolve/


Example alert response:

{
  "id": 213,
  "machine": "pi-exam-01",
  "severity": "high",
  "rule": "SSH brute-force",
  "message": "5 failed SSH login attempts from 192.168.1.5",
  "first_seen": "2025-02-12T18:10:44Z",
  "last_seen": "2025-02-12T18:12:03Z"
}

5. Final Module & Folder Organization

This is the definitive structure we will code against:

siem-lite/
│
├── core/
│   ├── utils.py
│   ├── mixins.py
│   ├── validators.py
│   └── base_models.py
│
├── machines/
│   ├── models.py
│   ├── serializers.py
│   ├── views.py
│   ├── urls.py
│   └── services/
│       └── auth_service.py
│
├── logs/
│   ├── models.py
│   ├── serializers.py
│   ├── ingestion.py
│   ├── views.py
│   ├── urls.py
│   └── pipeline/
│       ├── normalizer.py
│       ├── parser.py
│       └── enricher.py
│
├── rules/
│   ├── models.py
│   ├── engine.py
│   ├── serializers.py
│   ├── views.py
│   ├── urls.py
│
├── alerts/
│   ├── models.py
│   ├── engine.py
│   ├── serializers.py
│   ├── views.py
│   ├── urls.py
│
├── reports/
│   ├── pdf.py
│   ├── scheduler.py
│   └── views.py
│
├── dashboard/
│   ├── views.py
│   └── urls.py
