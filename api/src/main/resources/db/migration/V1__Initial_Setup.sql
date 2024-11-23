create table note (
  id bigint generated by default as identity, -- TODO create and use apposite new sequence instead of default
  content varchar(255),
  owner_username varchar(255),
  primary key (id)
);

create table roles (
  role_id integer generated by default as identity, -- TODO create and use apposite new sequence instead of default
  role_name varchar(20) check (role_name in ('ROLE_USER','ROLE_ADMIN')),
  primary key (role_id)
);

create table users (
  account_expiry_date date,
  account_non_expired boolean not null,
  account_non_locked boolean not null,
  credentials_expiry_date date,
  credentials_non_expired boolean not null,
  enabled boolean not null,
  is_two_factor_enabled boolean not null,
  role_id integer,
  created_date timestamp(6),
  updated_date timestamp(6),
  user_id bigint generated by default as identity, -- TODO create and use apposite new sequence instead of default
  username varchar(20) not null,
  email varchar(50) not null,
  password varchar(120),
  sign_up_method varchar(255),
  two_factor_secret varchar(255),
  primary key (user_id),
  unique (username),
  unique (email)
);

-- TODO rename constraint
alter table if exists users add constraint FKp56c1712k691lhsyewcssf40f foreign key (role_id) references roles;
