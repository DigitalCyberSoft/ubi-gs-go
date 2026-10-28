// Package crypto holds the game's message encodings: the keyless GS XOR scrambling, its Blowfish variant
// and the RSA-512 key exchange. None of them is real protection; they are what the 2006 client speaks.
package crypto

// ceilSqrt returns the smallest r with r*r >= n.
func ceilSqrt(n int) int {
	r := 0
	for r*r < n {
		r++
	}
	return r
}

func xorIndex(b []byte) {
	for i := range b {
		b[i] ^= byte(i - 119)
	}
}

// XOREncrypt scrambles a GS message payload: each byte is XORed with its index and the bytes are
// written along the diagonals of a square and read back by rows.
func XOREncrypt(in []byte) []byte {
	size := len(in)
	result := make([]byte, size)
	copy(result, in)
	xorIndex(result)

	root := ceilSqrt(size)
	grid := make([]int16, root*root)
	for i := range grid {
		grid[i] = -1
	}
	a, b := 0, 0
	for i := 0; i < size; i++ {
		if a < root {
			if b < 0 {
				b = a
				a = 0
			}
		} else {
			a = b + 2
			b = root - 1
		}
		grid[a+root*b] = int16(result[i])
		a++
		b--
	}
	idx := 0
	for j := 0; j < root; j++ {
		for k := 0; k < root; k++ {
			if v := grid[k+root*j]; v != -1 {
				result[idx] = byte(v)
				idx++
			}
		}
	}
	return result
}

// XORDecrypt reverses XOREncrypt.
func XORDecrypt(in []byte) []byte {
	size := len(in)
	result := make([]byte, size)
	root := ceilSqrt(size)
	// marks the cells the diagonal walk visits, then holds the input in row order
	used := make([]bool, root*root)
	cells := make([]byte, root*root)

	a, b := 0, 0
	for n := size; n > 0; n-- {
		if b < root {
			if a < 0 {
				a = b
				b = 0
			}
		} else {
			b = a + 2
			a = root - 1
		}
		used[b+root*a] = true
		a--
		b++
	}

	c, d, row := 0, 0, 0
	for d < size {
		if c >= root {
			row += root
			c = 0
		}
		if used[row+c] {
			cells[row+c] = in[d]
			d++
		}
		c++
	}

	e, f := 0, 0
	for i := 0; i < size; i++ {
		if f < root {
			if e < 0 {
				e = f
				f = 0
			}
		} else {
			f = e + 2
			e = root - 1
		}
		result[i] = cells[f+root*e]
		e--
		f++
	}
	xorIndex(result)
	return result
}
