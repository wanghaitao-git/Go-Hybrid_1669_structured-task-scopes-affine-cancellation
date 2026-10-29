package main

func write(p []int, done chan bool) {
	p[0] = 1
	done <- true
}

func main() {
	x := make([]int, 2)
	alias := x[:1]
	done := make(chan bool)
	go write(x, done)
	alias[0] = 1
	<-done
}
