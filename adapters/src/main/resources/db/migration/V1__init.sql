create table statement (
    id              uuid        primary key,
    customer_id     varchar(64) not null,
    filename        varchar(255) not null,
    size_bytes      bigint      not null check (size_bytes > 0),
    media_type      varchar(64) not null,
    sha256          bytea       not null,
    status          varchar(16) not null,
    rejection_reason varchar(255),
    storage_key     varchar(512) not null,
    encrypted_dek   bytea       not null,
    dek_key_id      varchar(64) not null,
    created_at      timestamptz not null default now(),
    created_by      varchar(128) not null,
    updated_at      timestamptz not null default now()
);
create index statement_customer_status_idx
    on statement (customer_id, status, created_at desc);
create index statement_status_quarantined_idx
    on statement (status, created_at) where status = 'QUARANTINED';

create table audit_event (
    id              bigserial   primary key,
    occurred_at     timestamptz not null default now(),
    event_type      varchar(32) not null,
    actor           varchar(128),
    actor_ip        inet,
    statement_id    uuid,
    link_token_hash bytea,
    detail          jsonb        not null default '{}'::jsonb,
    trace_id        varchar(32)
);
create index audit_event_statement_idx on audit_event (statement_id, occurred_at desc);
create index audit_event_type_time_idx on audit_event (event_type, occurred_at desc);
