package ratings

import (
	"testing"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/accounts"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
)

func vals(result, race int64, extra map[int]int64) []int64 {
	v := make([]int64, values)
	v[idxResult], v[idxRace] = result, race
	for k, x := range extra {
		v[k] = x
	}
	return v
}

func TestApply(t *testing.T) {
	a, b := accounts.Account{ID: 1, Name: "a"}, accounts.Account{ID: 2, Name: "b"}
	stored := map[int64]map[string]int64{1: {"RATING": 1600, "GAMES_PLAYED": 1, "AVERAGE_HERO_LEVEL": 4 << 16, "CUR_LOSSES_STREAK": 2}}
	out := Apply([]outcome{
		{a, vals(resultWon, 3, map[int]int64{idxTime: 600, idxAvgLevel: 6 << 16, 8 + 3: 2, idxDefeated: 1})},
		{b, vals(resultDisconnected, 9, map[int]int64{idxTime: -5, idxHeroesLost: 1})},
	}, stored)
	sa, sb := out[1], out[2]
	// the favourite wins: a small gain
	if sa["RATING"] != 1612 || sb["RATING"] != 1488 {
		t.Fatalf("ratings %d %d", sa["RATING"], sb["RATING"])
	}
	if sa["WINS"] != 1 || sa["GAMES_PLAYED"] != 2 || sa["CUR_WINS_STREAK"] != 1 || sa["CUR_LOSSES_STREAK"] != 0 || sa["MAX_WINS_STREAK"] != 1 ||
		sa["W_DUNGEON"] != 1 || sa["G_DUNGEON"] != 1 || sa["H_DUNGEON"] != 2 || sa["TOT_HEROES_HIRED"] != 2 || sa["TOT_HEROES_DEFEATED"] != 1 ||
		sa["TOT_TIME_PLAYED"] != 600 || sa["AVERAGE_HERO_LEVEL"] != 5<<16 {
		t.Fatalf("winner %v", sa)
	}
	// a disconnection is a loss; an unknown race and a negative time count nothing
	if sb["LOSSES"] != 1 || sb["DISCONNECTIONS"] != 1 || sb["TOT_TIME_PLAYED"] != 0 || sb["TOT_HEROES_LOST"] != 1 || sb["G_HEAVEN"] != 0 {
		t.Fatalf("loser %v", sb)
	}
	// two winners: no rating change between them
	out = Apply([]outcome{{a, vals(resultWon, 0, nil)}, {b, vals(resultWon, 0, nil)}}, nil)
	if out[1]["RATING"] != 1500 || out[2]["RATING"] != 1500 {
		t.Fatal("rating moved between winners")
	}
}

func TestParse(t *testing.T) {
	l := make(dl.List, 22)
	for i := range l {
		l[i] = dl.S("1")
	}
	if _, ok := parse(l); !ok {
		t.Fatal("22 numbers")
	}
	if _, ok := parse(l[:21]); ok {
		t.Fatal("21 values")
	}
	l[3] = dl.S("x")
	if _, ok := parse(l); ok {
		t.Fatal("not a number")
	}
}
