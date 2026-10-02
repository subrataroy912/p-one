CREATE TABLE app_users (
    id BINARY(16) NOT NULL,
    email VARCHAR(254) NOT NULL,
    password_hash VARCHAR(100) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    role VARCHAR(20) NOT NULL,
    active BIT NOT NULL,
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    CONSTRAINT pk_app_users PRIMARY KEY (id),
    CONSTRAINT uk_app_users_email UNIQUE (email)
);

CREATE TABLE auth_refresh_tokens (
    id BINARY(16) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    user_id BINARY(16) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    revoked_at DATETIME(6),
    created_at DATETIME(6) NOT NULL,
    CONSTRAINT pk_auth_refresh_tokens PRIMARY KEY (id),
    CONSTRAINT uk_auth_refresh_tokens_token_hash UNIQUE (token_hash),
    CONSTRAINT fk_auth_refresh_tokens_user
        FOREIGN KEY (user_id) REFERENCES app_users (id)
);

CREATE INDEX idx_auth_refresh_tokens_user_id ON auth_refresh_tokens (user_id);
