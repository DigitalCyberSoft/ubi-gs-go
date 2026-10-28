package limits

import "testing"

func TestCounts(t *testing.T) {
	l := New(3, 2)
	for _, c := range []struct {
		ip   string
		want bool
	}{{"1.1.1.1", true}, {"1.1.1.1", true}, {"1.1.1.1", false}, {"2.2.2.2", true}, {"3.3.3.3", false}} {
		if got := l.Acquire(c.ip); got != c.want {
			t.Fatalf("Acquire(%s) = %v", c.ip, got)
		}
	}
	l.Release("1.1.1.1")
	if !l.Acquire("3.3.3.3") {
		t.Fatal("slot not freed")
	}
	total, per := l.Counts()
	if total != 3 || per["1.1.1.1"] != 1 || per["2.2.2.2"] != 1 || per["3.3.3.3"] != 1 {
		t.Fatalf("%d %v", total, per)
	}
	l.Release("9.9.9.9") // unknown: no change
	if total, _ := l.Counts(); total != 3 {
		t.Fatal("released an unknown address")
	}
}
