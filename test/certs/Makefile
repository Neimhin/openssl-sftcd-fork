outer.key:
	openssl genpkey -algorithm RSA -out outer.key -pkeyopt rsa_keygen_bits:2048
outer.csr: outer.cnf outer.key
	openssl req -new -key outer.key -out outer.csr -config outer.cnf
outer.crt: outer.csr outer.key
	openssl x509 -req -in outer.csr -signkey outer.key -out outer.crt -days 365000 -extfile outer.cnf -extensions req_ext
outer.crt.txt: outer.crt
	openssl x509 -in $< -text -noout -out $@ # -noout tells openssl not to repeate the .crt PEM in the output

inner.key:
	openssl genpkey -algorithm RSA -out inner.key -pkeyopt rsa_keygen_bits:2048
inner.csr: inner.cnf inner.key
	openssl req -new -key inner.key -out inner.csr -config inner.cnf
inner.crt: inner.csr inner.key
	openssl x509 -req -in inner.csr -signkey inner.key -out inner.crt -days 365000 -extfile inner.cnf -extensions req_ext
inner.crt.txt: inner.crt
	openssl x509 -in $< -text -noout -out $@ # -noout tells openssl not to repeate the .crt PEM in the output
