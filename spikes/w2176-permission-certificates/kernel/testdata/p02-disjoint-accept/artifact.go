package main

func fill(p []int, v int, done chan bool) {
	p[0] = v
	done <- true
}

func main() {
	x := make([]int, 4)
	a := x[:2]
	b := x[2:4]
	d1 := make(chan bool)
	d2 := make(chan bool)
	go fill(a, 1, d1)
	go fill(b, 2, d2)
	<-d1
	<-d2
	x[0] = x[0] + x[2]
}
