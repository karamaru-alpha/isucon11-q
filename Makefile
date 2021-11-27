.PHONY: before
before:
# 同期
	sudo cp nginx.conf /etc/nginx/nginx.conf
	sudo cp my.cnf /etc/mysql/my.cnf
# ビルド
#	(cd go && go build -o webapp)
# 起動
	sudo systemctl restart nginx
	sudo systemctl restart mysql
#	sudo systemctl restart isucari.golang.service
# 掃除
	sudo rm /var/log/mysql/slow-query.log 2> /dev/null
	sudo rm /var/log/nginx/access.log 2> /dev/null


.PHONY: bench
bench:




.PHONY: kataru
kataru:
	if [ ! -f kataribe.toml ]; then kataribe -generate; fi
	(cd ../vagrant-isucon/isucon11-qualifier-standalone/ && vagrant ssh -c cat /var/log/mysql/slow-query.log) | kataribe
