// Package ratings turns the results of rated matches into ladder stats and Elo ratings (fork issue #49).
//
// At the end of a rated match every client submits, for every human player, 22 values from the game's
// NWorld::CPlayersStatsAccumulator (filled by 0x0085d260, read with 0x00d62ba0):
//
//	0      result: 1 won, 0 lost (defeated or surrendered), 2 removed/disconnected, -1 unset
//	1      race: 0 Haven, 1 Preserve (Sylvan), 2 Academy, 3 Dungeon, 4 Necropolis, 5 Inferno
//	2..7   creature recruitment value per creature faction (no ladder field uses it)
//	8..13  heroes per hero race (the starting heroes)
//	14     heroes lost
//	15     enemy heroes defeated
//	16     average hero level, 16.16 fixed point
//	17     time played, seconds
//	18..21 always 0
//
// The Profile screen shows TOT_TIME_PLAYED / 60 and AVERAGE_HERO_LEVEL / 65536 (0x009f6950), so the
// ladder keeps seconds and 16.16 fixed point too. The game computes no rating itself.
package ratings

import (
	"math"
	"strconv"
	"strings"

	"github.com/DigitalCyberSoft/ubi-gs-go/internal/accounts"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/dl"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/lobby"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/logx"
	"github.com/DigitalCyberSoft/ubi-gs-go/internal/proxy"
)

// Value indexes.
const (
	idxResult      = 0
	idxRace        = 1
	idxHeroesFirst = 8
	idxHeroesLost  = 14
	idxDefeated    = 15
	idxAvgLevel    = 16
	idxTime        = 17
	values         = 22
)

// Results of value 0.
const (
	resultLost         = 0
	resultWon          = 1
	resultDisconnected = 2
)

// K is the Elo K-factor.
const K = 32

// maxTime caps one match's time played (a week), against nonsense values.
const maxTime = 7 * 24 * 3600

// Ladder applies finished matches to the ladder.
type Ladder struct {
	Accounts *accounts.Store
	Log      *logx.Logger
}

type outcome struct {
	account accounts.Account
	values  []int64
}

func parse(l dl.List) ([]int64, bool) {
	if len(l) < values {
		return nil, false
	}
	out := make([]int64, values)
	for i := 0; i < values; i++ {
		s, ok := l.Str(i)
		if !ok {
			return nil, false
		}
		n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

// Key is the ladder a match counts for: the room's game and its game mode (1 Ranked, 2 1v1).
func Key(m *lobby.Match) string {
	id := m.Ladder
	if id <= 0 {
		id = 1
	}
	return proxy.LadderKey(m.Game, strconv.Itoa(id))
}

// MatchFinished implements lobby.Results.
func (l *Ladder) MatchFinished(m *lobby.Match) {
	players := map[string]bool{}
	for _, p := range m.Players {
		players[strings.ToLower(p)] = true
	}
	var outs []outcome
	seen := map[int64]bool{}
	for _, name := range m.Order {
		v, ok := parse(m.Values[name])
		if !ok {
			l.Log.Warnf("match %d: unreadable results for %s", m.ID, name)
			continue
		}
		account := m.Accounts[name]
		if account == nil || !players[strings.ToLower(account.Name)] || seen[account.ID] {
			l.Log.Warnf("match %d: results for %s, who isn't one of its players", m.ID, name)
			continue
		}
		if m.Disputed[name] {
			l.Log.Warnf("match %d: the players' results for %s disagree, not rated", m.ID, name)
			continue
		}
		seen[account.ID] = true
		outs = append(outs, outcome{*account, v})
	}
	if len(outs) == 0 {
		return
	}
	ids := make([]int64, len(outs))
	for i, o := range outs {
		ids[i] = o.account.ID
	}
	key := Key(m)
	err := l.Accounts.UpdateLadder(key, ids, func(stored map[int64]map[string]int64) map[int64]map[string]int64 {
		return Apply(outs, stored)
	})
	if err != nil {
		l.Log.Errorf("match %d: storing the results: %v", m.ID, err)
		return
	}
	for _, o := range outs {
		l.Log.Infof("match %d: %s result %d, ladder %s updated", m.ID, o.account.Name, o.values[idxResult], key)
	}
}

func won(v []int64) bool  { return v[idxResult] == resultWon }
func lost(v []int64) bool { return v[idxResult] == resultLost || v[idxResult] == resultDisconnected }

func pos(n int64) int64 { return max(n, 0) }

// Apply returns the new ladder fields of the players from their stored ones.
func Apply(outs []outcome, stored map[int64]map[string]int64) map[int64]map[string]int64 {
	stats := map[int64]map[string]int64{}
	for _, o := range outs {
		stats[o.account.ID] = proxy.Stats(stored[o.account.ID])
	}
	// Elo, pairwise between players with different outcomes
	delta := map[int64]float64{}
	for i, a := range outs {
		for j, b := range outs {
			if j <= i || !(won(a.values) && lost(b.values) || lost(a.values) && won(b.values)) {
				continue
			}
			ra, rb := float64(stats[a.account.ID]["RATING"]), float64(stats[b.account.ID]["RATING"])
			ea := 1 / (1 + math.Pow(10, (rb-ra)/400))
			sa := 0.0
			if won(a.values) {
				sa = 1
			}
			n := float64(len(outs) - 1)
			delta[a.account.ID] += K * (sa - ea) / n
			delta[b.account.ID] -= K * (sa - ea) / n
		}
	}
	out := map[int64]map[string]int64{}
	for _, o := range outs {
		s, v := stats[o.account.ID], o.values
		s["RATING"] = max(0, s["RATING"]+int64(math.Round(delta[o.account.ID])))
		s["GAMES_PLAYED"]++
		race := v[idxRace]
		raceName := ""
		if race >= 0 && race < 6 {
			raceName = proxy.Races[race]
		}
		switch {
		case won(v):
			s["WINS"]++
			s["CUR_WINS_STREAK"]++
			s["CUR_LOSSES_STREAK"] = 0
			s["MAX_WINS_STREAK"] = max(s["MAX_WINS_STREAK"], s["CUR_WINS_STREAK"])
			if raceName != "" {
				s["W_"+raceName]++
			}
		case lost(v):
			s["LOSSES"]++
			s["CUR_LOSSES_STREAK"]++
			s["CUR_WINS_STREAK"] = 0
			s["MAX_LOSSES_STREAK"] = max(s["MAX_LOSSES_STREAK"], s["CUR_LOSSES_STREAK"])
			if raceName != "" {
				s["L_"+raceName]++
			}
		}
		if v[idxResult] == resultDisconnected {
			s["DISCONNECTIONS"]++
		}
		if raceName != "" {
			s["G_"+raceName]++
		}
		s["TOT_TIME_PLAYED"] += min(pos(v[idxTime]), maxTime)
		for r := 0; r < 6; r++ {
			h := min(pos(v[idxHeroesFirst+r]), 1000)
			s["TOT_HEROES_HIRED"] += h
			s["H_"+proxy.Races[r]] += h
		}
		s["TOT_HEROES_LOST"] += min(pos(v[idxHeroesLost]), 1000)
		s["TOT_HEROES_DEFEATED"] += min(pos(v[idxDefeated]), 1000)
		// running mean over the games played, in 16.16 fixed point
		games := s["GAMES_PLAYED"]
		level := min(pos(v[idxAvgLevel]), 100<<16)
		s["AVERAGE_HERO_LEVEL"] = (s["AVERAGE_HERO_LEVEL"]*(games-1) + level) / games
		out[o.account.ID] = s
	}
	return out
}
