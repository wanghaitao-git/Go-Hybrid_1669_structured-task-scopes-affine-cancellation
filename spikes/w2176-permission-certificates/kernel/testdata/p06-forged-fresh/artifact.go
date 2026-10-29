package main

func write(p []int, done chan bool) {
	p[0] = 1
	done <- true
}

func main() {
	x := make([]int, 2)
	y := x
	done := make(chan bool)
	go write(y, done)
	<-done
	x[0] = 9
}
