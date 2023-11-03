create table role (
    roleid bigserial primary key,
    role varchar(20) not null,
    description varchar(100) not null
);

insert into role(role, description) values ('ADMIN', 'system admin');
insert into role(role, description) values ('USER', 'user');