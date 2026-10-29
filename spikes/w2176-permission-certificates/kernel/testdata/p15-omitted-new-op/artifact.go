package main

func write(p []int, done chan bool) {
	p[0] = 1
	done <- true
}

func main() {
	x := make([]int, 2)
	x[0] = 7
	done := make(chan bool)
	go write(x, done)
	<-done
	x[1] = x[0] + 1; x[0] = 5
}
