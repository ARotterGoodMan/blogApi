create database MyBlog;

use MyBlog;

create table Users
(
    id         int auto_increment primary key,
    username   varchar(50)        not null,
    password   varchar(255)       not null,
    salt       varchar(255)       not null,
    phone      varchar(15)        not null unique,
    email      varchar(100)       not null unique,
    Admin      int      default 0 null,
    token      varchar(255)       null,
    created_at datetime default current_timestamp
);
