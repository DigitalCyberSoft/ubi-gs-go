package h5

import (
	"fmt"
	"testing"
	"time"
)

func TestOptionsRepeatedKey(t *testing.T) {
	in := []Option{
		{Key: []byte("a"), Int: 1, Value: []byte("x\x00")},
		{Key: []byte("b"), Int: 2, Value: []byte("y\x00")},
		{Key: []byte("a"), Int: 3, Value: []byte("z\x00")},
	}
	got, err := readOptions(writeOptions(in))
	if err != nil {
		t.Fatal(err)
	}
	// the first position, the last value
	if len(got) != 2 || string(got[0].Key) != "a" || got[0].Int != 3 || string(got[0].Value) != "z\x00" ||
		string(got[1].Key) != "b" || got[1].Int != 2 {
		t.Fatalf("options %+v", got)
	}
}

// Any lobby client sends a room info, so thousands of keys must not take quadratic time (a lock is held
// while it is read): 20000 keys took about 1.5 s when each key was compared with all the others.
func TestOptionsManyKeys(t *testing.T) {
	in := make([]Option, 20000)
	for i := range in {
		in[i] = Option{Key: fmt.Appendf(nil, "key%05d", i), Value: []byte{}}
	}
	buf := writeOptions(in)
	start := time.Now()
	got, err := readOptions(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(in) {
		t.Fatalf("%d options, want %d", len(got), len(in))
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("%d keys took %v", len(in), d)
	}
}
