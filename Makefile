.PHONY: before
before:
# 同期
	sudo cp nginx.conf /etc/nginx/nginx.conf
	sudo cp my.cnf /etc/mysql/my.cnf
# ビルド
#	(cd go && go build -o webapp)
# 掃除
	sudo rm /var/log/mysql/slow-query.log 2> /dev/null
	sudo rm /var/log/nginx/access.log 2> /dev/null
	sudo touch /var/log/mysql/slow-query.log
	sudo chown -R mysql /var/log/mysql/slow-query.log
	sudo touch /var/log/nginx/access.log
# 起動
	sudo systemctl restart nginx
	sudo systemctl restart mysql
#	sudo systemctl restart isucari.golang.service


.PHONY: bench
bench:
	(cd ../bench && sudo ./bench -all-addresses 127.0.0.11 -target 127.0.0.11:443 -tls -jia-service-url http://127.0.0.1:4999)

.PHONY: kataru
kataru:
	sudo cat /var/log/nginx/access.log | kataribe

.PHONY: slow
slow:
	sudo pt-query-digest /var/log/mysql/slow-query.log
