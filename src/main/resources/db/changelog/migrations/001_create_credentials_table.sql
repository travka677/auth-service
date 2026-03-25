--liquibase formatted sql

--changeset dev:001-create-credentials-table
CREATE TABLE credentials
(
    id            UUID         DEFAULT gen_random_uuid() NOT NULL,
    user_id       UUID                                   NOT NULL,
    username      VARCHAR(255)                           NOT NULL,
    password_hash VARCHAR(255)                           NOT NULL,
    role          VARCHAR(50)                            NOT NULL,
    created_at    TIMESTAMP    DEFAULT now()             NOT NULL,
    updated_at    TIMESTAMP    DEFAULT now()             NOT NULL,

    CONSTRAINT pk_credentials PRIMARY KEY (id),
    CONSTRAINT uq_credentials_user_id UNIQUE (user_id),
    CONSTRAINT uq_credentials_username UNIQUE (username)
);

--changeset dev:001-create-credentials-indexes
CREATE INDEX idx_credentials_user_id ON credentials (user_id);
CREATE INDEX idx_credentials_username ON credentials (username);
