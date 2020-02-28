sudo docker run -p 3306:3306 --security-opt seccomp:/home/dawn/Downloads/speaker/profile1/booting.json -e MYSQL_ROOT_PASSWORD=123 -d percona

sudo docker run -p 3306:3306 -e MYSQL_ROOT_PASSWORD=123 -d percona


mysqlslap -h127.0.0.1 -uroot -p123  --concurrency=50 --iterations=10 --auto-generate-sql --verbose

mysqlslap -h127.0.0.1 -uroot -p123  --concurrency=50 --iterations=100 --number-int-cols=5 --number-char-cols=20 --auto-generate-sql --verbose

mysqlslap -h127.0.0.1 -uroot -p123 --concurrency=3 --iterations=50 --auto-generate-sql --auto-generate-sql-load-type=mixed --auto-generate-sql-add-autoincrement --engine=innodb --number-of-queries=50

sudo mysqlslap -h127.0.0.1 -uroot -p123  --concurrency=10 --iterations=2 --create-schema=employees_backup --query="/mysqlslap_tutorial/capture_queries.sql" --verbose

docker stop hash -t 900 


Supply your own create and query SQL statements, with 50 clients querying and 200 selects for each

mysqlslap -h127.0.0.1 -uroot -p123 --delimiter=";" --create="CREATE TABLE a (b int);INSERT INTO a VALUES (23)" --query="SELECT * FROM a" --concurrency=5 --iterations=20


Let mysqlslap build the query SQL statement with a table of two INT columns and three VARCHAR columns. Use five clients querying 20 times each. Do not create the table or insert the data (that is, use the previous test's schema and data):

mysqlslap -h127.0.0.1 -uroot -p123 --concurrency=5 --iterations=20 --number-int-cols=2 --number-char-cols=3 --auto-generate-sql


mysqlslap -h127.0.0.1 -uroot -p123 --delimiter=";" --create="CREATE TABLE a (b int);INSERT INTO a VALUES (23)" --query="SELECT * FROM a" --concurrency=5 --iterations=20

mysqlslap -h127.0.0.1 -uroot -p123 --concurrency=3 --iterations=50 --auto-generate-sql --auto-generate-sql-load-type=mixed --auto-generate-sql-add-autoincrement --engine=innodb --number-of-queries=50

mysqlslap -h127.0.0.1 -uroot -p123 --concurrency=5 --iterations=5 --query=query.sql --create=create.sql --delimiter=";"

mysqladmin -h127.0.0.1 -uroot -p123 password 1234 --ssl
sudo mysqladmin -h127.0.0.1 -uroot -p1234 ping

watch -n 1 "dmesg| tail -4"




sudo docker run -p 3306:3306 --security-opt seccomp:../Profile/booting_kill_default.json -e MYSQL_ROOT_PASSWORD=123 -d percona

