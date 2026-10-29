package main

func compute(p []int, done chan bool) {
	p[0] = 41
	done <- true
}

func main() {
	x := make([]int, 1)
	done := make(chan bool)
	go compute(x, done)
	<-done
	x[0] = x[0] + 1
}
