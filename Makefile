.PHONY: setup
setup:
	sudo apt install -y percona-toolkit git unzip
	git init
	git config --global user.name karamaru-alpha
	git config --global user.email mrnk3078@gmail.com
	git config credential.helper store
	wget https://github.com/matsuu/kataribe/releases/download/v0.4.1/kataribe-v0.4.1_linux_amd64.zip -O kataribe.zip
	unzip -o kataribe.zip
	sudo mv kataribe /usr/local/bin/
	sudo chmod +x /usr/local/bin/kataribe
	sudo rm kataribe.zip
	kataribe -generate
	sudo rm README.md 2> /dev/null
	sudo rm LICENSE 2> /dev/null

.PHONY: before
before:
# 同期
	git stash
	git pull origin main
	sudo cp nginx.conf /etc/nginx/nginx.conf
	sudo cp my.cnf /etc/mysql/my.cnf
# ビルド
	(cd go && go build -o isucondition)
# 掃除
	sudo rm /var/log/mysql/slow-query.log 2> /dev/null
	sudo rm /var/log/nginx/access.log 2> /dev/null
	sudo touch /var/log/mysql/slow-query.log
	sudo chown -R mysql /var/log/mysql/slow-query.log
	sudo touch /var/log/nginx/access.log
# 起動
	sudo systemctl restart nginx
	sudo systemctl restart mysql
	sudo systemctl restart isucondition.go.service


.PHONY: bench
bench:
	(cd ../bench && sudo ./bench -all-addresses 127.0.0.11 -target 127.0.0.11:443 -tls -jia-service-url http://127.0.0.1:4999)

.PHONY: kataru
kataru:
	sudo cat /var/log/nginx/access.log | kataribe

.PHONY: slow
slow:
	sudo pt-query-digest /var/log/mysql/slow-query.log
