package main

func write(p []int, done chan bool) {
	p[0] = 1
	done <- true
}

func main() {
	x := make([]int, 2)
	done := make(chan bool)
	go write(x[:1], done)
	x[0] = 9
	<-done
}
