# Build from source

[Back to the overview](../README.md)

This repository contains the desktop app, sensor, dashboard, and local server.
Pattern rules work without any service. Model-backed checks use the Intelligence
service, and new local workspaces enroll in the free allowance automatically
when the hosted free service is enabled.

## macOS (Apple Silicon)

Install **Docker Desktop** and **Python 3.11+**, then run:

```sh
git clone https://github.com/opensecurainc/openaidr.git
cd openaidr
./setup.sh
```

Setup downloads and verifies the newest complete release, including
prereleases, installs the app, starts the local server, and opens the app and
dashboard. Configuration and credentials are stored in
`~/Library/Application Support/OpenAIDR/local` and reused on later runs. Create
an enrollment link under **Administration > App Enrollment** and paste it into
the app.

## Windows, Linux, or a source build

Install **Docker with Compose** and **Python 3.11+**, then start the server and
dashboard from a clean committed clone:

```sh
python3 scripts/local_stack.py configure
docker compose up --build -d
```

Open <http://localhost:8080> and sign in as `admin@localhost` with the generated
`OPENAIDR_ADMIN_PASSWORD` in `.env`. Keep that file private. Then follow the
[desktop build instructions](guide.md#build-the-app) to build and enroll
the app. The Compose setup is for local development and evaluation, not
production. Building from a downloaded archive needs extra environment
variables; see [local server setup](guide.md#start-the-local-server).
