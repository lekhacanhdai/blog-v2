CREATE TABLE users (
    userid BIGSERIAL PRIMARY KEY NOT NULL,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(50) NOT NULL,
    email VARCHAR(100),
    active BOOLEAN,
    roleid bigint NOT NULL,
    FOREIGN KEY (roleid) references role(roleid)
);