--liquibase formatted sql

--changeset dev:002-create-refresh-tokens-table
CREATE TABLE refresh_tokens
(
    id             UUID         DEFAULT gen_random_uuid() NOT NULL,
    token          TEXT                                   NOT NULL,
    credentials_id UUID                                   NOT NULL,
    expires_at     TIMESTAMP                              NOT NULL,
    revoked        BOOLEAN      DEFAULT false             NOT NULL,
    created_at     TIMESTAMP    DEFAULT now()             NOT NULL,
    updated_at     TIMESTAMP    DEFAULT now()             NOT NULL,

    CONSTRAINT pk_refresh_tokens PRIMARY KEY (id),
    CONSTRAINT uq_refresh_tokens_token UNIQUE (token),
    CONSTRAINT fk_refresh_tokens_credentials
        FOREIGN KEY (credentials_id) REFERENCES credentials (id)
            ON DELETE CASCADE
);

--changeset dev:002-create-refresh-tokens-indexes
CREATE INDEX idx_refresh_tokens_credentials_id ON refresh_tokens (credentials_id);
