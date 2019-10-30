package probe

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParallelSearch(t *testing.T) {
	const numRoutines = 10

	doTest := func(t *testing.T, start, end, n int) {
		s := parallelSearch{
			predicate:   func(i int) (bool, error) { return i >= n, nil },
			memoized:    map[int]bool{},
			numRoutines: numRoutines,
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

	for start := 0; start < 1000; start = start + 99 {
		for end := start + 99; end < 1000; end = end + 100 {
			for n := start; n <= end; n = n + 49 {
				doTest(t, start, end, n)
			}
		}
	}
}
