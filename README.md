# Mill ERP server

A real server for the Mill HR portal. No packages to install. It needs Node 22 or newer.

## Run it

    node server.js

Open http://localhost:3000, choose "Register a new company", and you become the Managing Director (ID E-1000).
Tick the sample-data box to look around with 96 demo employees, or leave it empty to start your own mill.

Settings (environment variables): `PORT` (default 3000), `DB_FILE` (default `data.db` next to server.js).

With Docker:

    docker build -t mill-erp .
    docker run -p 3000:3000 -v mill-data:/data mill-erp

## What the server does

- Every company (mill) has its own code and its own data. One company can never see another company's data.
- Real sign-in with Company code, Employee ID and password. Passwords are stored with scrypt and a random salt. Wrong password 5 times locks that ID for 5 minutes. Sessions last 12 hours.
- New staff use "Sign up". HR or the MD approves the request, then the person can sign in.
- Data is saved in SQLite (`data.db`). Each change is checked on the server:
  - HR and the MD can change anything.
  - Everyone else can only change records about themselves or the people under them in the organogram. They cannot change employees, workflows or sign-up requests.
  - If two people change the same data at once, the second save is refused and that person is told to redo it, so nothing is silently overwritten.
- Every sign-in and save is written to an audit table.

## Before you put it on the internet

1. Put it behind HTTPS (for example Caddy or nginx). Without HTTPS passwords travel in the clear.
2. Back up `data.db` every day (copy it while the server is stopped, or use `sqlite3 data.db ".backup file"`).
3. The approval chain is still decided inside the browser page, and the server only checks who may change which records. For strict control, move the approval rules to the server next.
4. SQLite is fine for one mill or a few. For many mills at once, move storage to PostgreSQL.

## Files

- `server.js` the whole server
- `public/index.html` the portal
