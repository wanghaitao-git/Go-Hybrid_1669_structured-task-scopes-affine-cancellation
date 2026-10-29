package main

type counter struct {
	n int
}

func bump(c *counter, done chan bool) {
	c.n++
	done <- true
}

func main() {
	c := &counter{}
	d1 := make(chan bool)
	d2 := make(chan bool)
	go bump(c, d1)
	go bump(c, d2)
	<-d1
	<-d2
}
