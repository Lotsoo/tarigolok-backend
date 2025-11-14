# Tari Golok - Backend (Gin + GORM)

Minimal scaffold for the Tari Golok backend using Gin, GORM and Postgres.

Features included in scaffold:
- Register / Login (bcrypt + JWT)
- Role support (user / admin)
- Video CRUD (admin can create)
- Submissions (user can submit link + note)
- Admin feedback endpoint for submissions
- .env support via `godotenv`

How to run (local / VPS):

1. Create a Postgres database and user.
2. Copy `.env.example` to `.env` and set values.
3. Build the binary:

```fish
go build -o tari-golok ./cmd/server
```

4. Run the binary (it reads `.env`):

```fish
./tari-golok
```

Production notes:
- This scaffold uses `AutoMigrate` for convenience. For production use, replace with proper SQL migrations (golang-migrate).
- Use a secure `JWT_SECRET` and manage `.env` carefully (do not commit secrets).
- Example `systemd` unit is provided in `systemd.example` section of this README.
