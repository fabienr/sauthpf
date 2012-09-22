#!/bin/sh

if [ $# -ne 1 ];then
	echo "Usage: $0 <path_to_sqlite_db>"
	exit 1
fi

sqlite3 $1 "CREATE TABLE sessions (ip varchar(64) primary key, user varchar(255), expire_date integer, start_time integer);"
sqlite3 $1 "CREATE TABLE log (ip varchar(64), user varchar(255), start_time integer, action_type integer, event_time integer);"
