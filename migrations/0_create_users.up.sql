create table users (
    id bigserial primary key,
    name varchar(50) not null,
    email varchar(50) unique,
    picture_url varchar(256),
    password_hash varchar(100), -- if null, then signed up with oauth
    verification_token uuid not null unique,
    verified boolean not null default false,
    refresh_token varchar(32)
);
