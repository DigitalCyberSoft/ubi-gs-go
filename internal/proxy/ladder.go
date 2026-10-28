package proxy

// Races in the game's ladder field names.
var Races = []string{"HEAVEN", "PRESERVE", "ACADEMY", "DUNGEON", "NECROMANCY", "INFERNO", "DWARVES"}

// Fields are the 42 fields the game reads from a ladder row (table 0x00b1b1e0).
var Fields = func() []string {
	f := []string{"RATING", "GAMES_PLAYED", "WINS", "LOSSES", "MAX_WINS_STREAK", "MAX_LOSSES_STREAK",
		"CUR_WINS_STREAK", "CUR_LOSSES_STREAK", "TOT_TIME_PLAYED", "TOT_HEROES_HIRED", "TOT_HEROES_LOST",
		"TOT_HEROES_DEFEATED"}
	for _, kind := range []string{"W", "L", "H", "G"} {
		for _, race := range Races {
			f = append(f, kind+"_"+race)
		}
	}
	return append(f, "AVERAGE_HERO_LEVEL", "DISCONNECTIONS")
}()

// StartRating is every player's rating before their first rated game.
const StartRating = 1500

// Stats returns all fields for a player: the stored values over the defaults.
func Stats(stored map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(Fields))
	for _, f := range Fields {
		out[f] = 0
	}
	out["RATING"] = StartRating
	for k, v := range stored {
		out[k] = v
	}
	return out
}
