SIEM-Lite: Open-Source Security Audit & Monitoring Platform

SIEM-Lite is an open-source, lightweight Security Information & Event Management (SIEM) platform designed for developers, system administrators, DevSecOps engineers, and security enthusiasts who need a modern and minimal SIEM for Linux systems.

The platform provides:

Log collection agents for Linux

Centralized ingestion API

Security rule engine (SSH brute-force, sudo abuse, port scans…)

Alerting (email/Telegram)

Dashboards for logs & alerts

Optional machine learning extensions

Nginx/Gunicorn deployment support

Full 21-day roadmap for contributors

SIEM-Lite is intentionally modular, transparent, easy to deploy, and friendly to beginners learning cybersecurity and backend engineering.

Table of Contents

Project Overview

Key Features

Architecture

Tech Stack

Installation

Environment Variables

Running the Project

Project Structure

Roadmap

Contributing

License

Project Overview

SIEM-Lite is a Django-based security audit and monitoring platform for Linux environments.

It collects, normalizes, stores, and analyzes logs received from multiple Linux machines, then applies a rule engine to detect suspicious behaviors—such as SSH brute-force attempts or port scans.

The name “Lite” does not mean simplistic—only that the platform is lightweight, open-source, modular, and easy to extend.

This project is intended to be:

A learning path for individuals exploring cybersecurity, DevSecOps, and backend engineering

A foundation for organizations needing a custom SIEM solution

A clear demonstration of secure coding, architecture, DevOps workflows, and defensive programming

Key Features
1. Log Ingestion API

JSON-based ingestion endpoint

JWT authentication

Secure machine registration

Supports standard Linux logs:

/var/log/auth.log

SSH login failures

sudo events

custom events

2. Security Rule Engine

Detects patterns such as:

SSH brute-force attacks

Port scans

Sudo misuse

File integrity modifications

Suspicious network connections

Rules support sliding windows, thresholds, and severity scoring.

3. Alerting Engine

Deduplication of repeated alerts

Escalation levels

Email or Telegram notifications

4. Dashboard

Machine overview

Alert center

Log explorer

Filtering by time, severity, machine, event type

5. Reporting

Daily/weekly PDF reports

Summaries of alerts, machine activity, anomalies

6. Linux Agent

A lightweight agent (Python/Bash) that:

Reads logs

Normalizes events

Sends to API with JWT

Buffers locally on failures

7. Deployment Ready

Nginx reverse proxy

Gunicorn workers

PostgreSQL database

Systemd services

Hardened settings

Architecture
Linux Agent  →  Django API  →  Rule Engine  →  Alerts & Dashboard

Components

Linux Agent

Collects logs & sys events

Sends JSON payloads

Django REST Backend

Token-based authentication

Normalization pipeline

Rule Engine

Pattern detection

Sliding window logic

Alert Engine

Prevents duplicates

Sends notifications

Dashboard

Visual analytics

Machine management

Log insights

Tech Stack

Backend: Django 5, Django REST Framework

Async/WS: Daphne (ASGI)

Database: PostgreSQL

Package Manager: uv

Agent: Python/Bash

Auth: JWT (SimpleJWT)

Infrastructure: Docker, Nginx, Gunicorn

CI: GitHub Actions

Pre-commit hooks: Ruff + pre-commit

Installation
1. Clone the repository
git clone https://github.com/<your-username>/siem-lite.git
cd siem-lite

2. Install dependencies using uv
uv sync --dev

3. Create your .env
DJANGO_SECRET_KEY=dev-secret
DJANGO_DEBUG=True

DB_NAME=siem_lite
DB_USER=siem_user
DB_PASSWORD=siem_password
DB_HOST=127.0.0.1
DB_PORT=5432

ALLOWED_HOSTS=127.0.0.1,localhost

4. Apply migrations
uv run python manage.py migrate

5. Create a superuser
uv run python manage.py createsuperuser

6. Start the server
uv run python manage.py runserver

Environment Variables
Variable	Description
DJANGO_SECRET_KEY	Django secret key
DJANGO_DEBUG	Debug mode
DB_NAME	PostgreSQL DB name
DB_USER	DB username
DB_PASSWORD	DB password
DB_HOST	DB host
DB_PORT	DB port
ALLOWED_HOSTS	Django allowed hosts
Project Structure
siem-lite/
│
├── config/              # Django project
│   ├── settings.py
│   ├── urls.py
│   ├── asgi.py
│   └── wsgi.py
│
├── core/                # Shared utilities & base logic
├── machines/            # Machine registration & auth
├── logs/                # Log ingestion & storage
├── alerts/              # Alert engine & severity logic
├── rules/               # Security rules & detection logic
├── reports/             # PDF generation & email delivery
├── dashboard/           # UI endpoints for admin portal
│
├── agent/               # Linux agent (Python/Bash)
├── .github/workflows    # CI/CD pipelines
├── .pre-commit-config.yaml
├── .gitignore
├── README.md
└── pyproject.toml

Roadmap

The project follows a structured 21-day execution roadmap:

Day 1–3: Foundations

Project setup

PostgreSQL config

Base models (Machine, LogEntry, Alert, Rule)

Day 4–8: Engines

Ingestion API

Rule engine

Alert engine

Day 9–13: Agent & Monitoring

Linux agent development

File & network monitoring

Security hardening

Day 14–18: Dashboard & Reporting

UI

Charts

PDF reports

Day 19–21: Deployment & QA

Docker + Nginx

CI/CD pipelines

Documentation

Portfolio-ready demos

Contributing

Contributions are welcome. This project is designed to be extended:

Add new detection rules

Improve visualization dashboards

Enhance the agent

Add ML-based anomaly detection

Integrate new data sources

Steps

Fork the repo

Create a feature branch

Follow pre-commit formatting/linting

Submit a pull request

License

This project is distributed under the MIT License, meaning you can use it, modify it, and distribute it freely with attribution.

Final Note

SIEM-Lite is more than a project; it's a complete learning journey through backend development, cybersecurity, distributed systems, and clean architecture.

If you like this project, please star the repository!
