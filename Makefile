test:
	go test

bench:
	go test -bench=Bench -benchmem .

fuzz:
	go test -fuzz .
