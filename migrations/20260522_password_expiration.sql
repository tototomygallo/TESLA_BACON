IF SCHEMA_ID(N'lab') IS NULL
    EXEC(N'CREATE SCHEMA lab');
GO

IF OBJECT_ID(N'lab.usuarios', N'U') IS NULL
    THROW 50000, 'No existe la tabla lab.usuarios. Crear la tabla base antes de aplicar esta migracion.', 1;
GO

IF COL_LENGTH(N'lab.usuarios', N'password_changed_at') IS NULL
BEGIN
    ALTER TABLE lab.usuarios
        ADD password_changed_at datetime NULL;
END
GO

IF COL_LENGTH(N'lab.usuarios', N'force_password_change') IS NULL
BEGIN
    ALTER TABLE lab.usuarios
        ADD force_password_change bit NOT NULL
            CONSTRAINT DF_usuarios_force_password_change DEFAULT (0);
END
GO

UPDATE lab.usuarios
SET password_changed_at = ISNULL(password_changed_at, ISNULL(updated_at, ISNULL(created_at, GETDATE())))
WHERE password_changed_at IS NULL;
GO
