package probe

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMinBinarySearch(t *testing.T) {
	doTest := func(t *testing.T, start, end, n int) {
		s := minBinarySearch{
			predicate: func(i int) (bool, error) { return i >= n, nil },
			memoized:  map[int]bool{},
		}
		expected := n
		if expected >= end {
			expected = -1
		}
		actual, err := s.search(start, end)
		require.NoError(t, err)
		require.Equal(
			t, expected, actual,
			"start: %d, end: %d, predicate: i >= %d",
			start, end, n,
		)
	}

	for start := 0; start <= 7; start++ {
		for end := start + 1; end <= 8; end++ {
			for n := start; n <= end; n++ {
				doTest(t, start, end, n)
			}
		}
	}
}
