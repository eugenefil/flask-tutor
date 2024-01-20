create table user(
	id integer primary key autoincrement,
	name text not null unique,
	password text not null
);

create table post(
	id integer primary key autoincrement,
	ctime integer not null default (unixepoch()),
	author_id integer not null,
	title text not null,
	content text not null,
	foreign key (author_id) references user (id)
);
