package lobby

import (
	"testing"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
)

func TestDisagreementWithoutTheFinisher(t *testing.T) {
	alice, bob, carol := &client{}, &client{}, &client{}
	one, zero := dl.List{dl.S("1")}, dl.List{dl.S("0")}
	m := &Match{Values: map[string]dl.List{"x": one, "y": one}, Disputed: map[string]bool{}, reports: map[string]map[*client]dl.List{
		"x": {bob: one, carol: zero}, // the finisher didn't report x
		"y": {alice: one, bob: one},  // agreed
	}}
	m.settle(alice)
	if !m.Disputed["x"] || m.Disputed["y"] {
		t.Fatalf("disputed %v", m.Disputed)
	}
}
