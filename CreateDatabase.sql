create database MyBlog;

use MyBlog;

create table Users
(
    id         int auto_increment primary key,
    username   varchar(50)        not null,
    password   varchar(255)       not null,
    salt       varchar(255)       not null,
    email      varchar(100)       not null unique,
    Admin      int      default 0 null,
    created_at datetime default current_timestamp
);


create table Login
(
    id         int auto_increment primary key,
    user_id    int          not null,
    token      varchar(255) null,
    ip_address varchar(45)  not null,
    created_at datetime default current_timestamp,
    foreign key (user_id) references Users (id)
);

# 删除字段
alter table Users
    drop column phone;

create table UserProfile
(
    id          int auto_increment primary key,
    user_id     int                       not null,
    name        varchar(100)              not null,
    sex         enum ('男', '女', '保密') not null,
    birth_date  date                      null,
    phone       varchar(20)               null,
    address     varchar(255)              null,
    city        varchar(100)              null,
    country     varchar(100)              null,
    postal_code varchar(20)               null,
    foreign key (user_id) references Users (id)
);