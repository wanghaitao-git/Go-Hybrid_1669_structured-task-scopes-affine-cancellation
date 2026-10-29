package main

func fill(p []int, v int, done chan bool) {
	p[0] = v
	done <- true
}

func main() {
	x := make([]int, 4)
	d1 := make(chan bool)
	d2 := make(chan bool)
	go fill(x[:3], 1, d1)
	go fill(x[2:4], 2, d2)
	<-d1
	<-d2
}
