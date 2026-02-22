# DB Notes

- The application uses SQLAlchemy and auto-creates tables on startup (`Base.metadata.create_all`).
- Run `setup_sqlserver.sql` once to create database and app login/user.
- After first app startup, default master records are auto-seeded:
  - statuses
  - asset types
  - departments
  - locations
  - manufacturers
  - vendors

If you need strict controlled schema migration later, add Alembic and versioned migrations.
