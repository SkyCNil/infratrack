/*
  SQL Server initial setup script for ITAM.
  Run as a SQL Server admin user.
*/

IF DB_ID('itam_db') IS NULL
BEGIN
  CREATE DATABASE itam_db;
END
GO

USE itam_db;
GO

IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name = 'apitam_user')
BEGIN
  CREATE LOGIN apitam_user WITH PASSWORD = 'StrongPassword123!';
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'apitam_user')
BEGIN
  CREATE USER apitam_user FOR LOGIN apitam_user;
END
GO

ALTER ROLE db_datareader ADD MEMBER apitam_user;
ALTER ROLE db_datawriter ADD MEMBER apitam_user;
ALTER ROLE db_ddladmin ADD MEMBER apitam_user;
GO

PRINT 'ITAM database and user setup complete.';
