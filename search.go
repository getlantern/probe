package probe

import (
	"math"
	"sort"
	"sync"

	"github.com/getlantern/errors"
)

// range over (start, end].
type intRange struct {
	start, end int
}

func (r intRange) len() int {
	return r.end - r.start
}

func (r intRange) split(n int) []intRange {
	var (
		splits = make([]intRange, 0, n)

		lenOverN  = float64(r.len()) / float64(n)
		perSplit  = int(math.Max(1, math.Round(lenOverN)))
		numSplits = int(math.Min(float64(n), float64(r.len())))
	)

	current := r.start
	for i := 0; i < numSplits-1; i++ {
		splits = append(splits, intRange{current, current + perSplit})
		current = current + perSplit
	}
	if current != r.end {
		splits = append(splits, intRange{current, r.end})
	}
	return splits
}

type parallelSearch struct {
	// predicate(i) should be deterministic.
	predicate func(i int) (bool, error)

	// numRoutines must be >= 4.
	numRoutines int

	memoized     map[int]bool
	memoizedLock sync.RWMutex
}

func newParallelSearch(predicate func(i int) (bool, error), numRoutines int) *parallelSearch {
	return &parallelSearch{predicate, numRoutines, map[int]bool{}, sync.RWMutex{}}
}

func (s *parallelSearch) check(i int) (bool, error) {
	// Note: we may get routines overwriting each other, but it should not matter as s.predicate(i)
	// is deterministic. We only need a lock here because Go complains without it.

	s.memoizedLock.RLock()
	if v, ok := s.memoized[i]; ok {
		s.memoizedLock.RUnlock()
		return v, nil
	}
	s.memoizedLock.RUnlock()

	v, err := s.predicate(i)
	if err != nil {
		return false, err
	}

	s.memoizedLock.Lock()
	s.memoized[i] = v
	s.memoizedLock.Unlock()

	return v, nil
}

func (s *parallelSearch) search(start, end int) (int, error) {
	if s.numRoutines < 4 {
		// This restriction is emergent from the logic and integer math below.
		return 0, errors.New("must specify at least 4 goroutines for parallel search")
	}

	// We are searching for the integer at which the predicate flips from false to true. We will
	// call this the target. We split up the range [start, end) and try to determine in which split
	// the target lies. When we find this split, we further sub-divide and search the sub-splits. We
	// repeat this process until we've narrowed our search to a range of size 1.

	type checkResult struct {
		checked int
		result  bool
		err     error
	}

	currentRange := intRange{start, end}
	for currentRange.len() > 1 {
		var (
			splits      = currentRange.split(s.numRoutines / 2)
			resultsChan = make(chan checkResult, len(splits)*2)
			wg          = new(sync.WaitGroup)
		)

		check := func(i int) {
			r, err := s.check(i)
			resultsChan <- checkResult{i, r, err}
			wg.Done()
		}

		for _, split := range splits {
			wg.Add(2)
			go check(split.start)
			go check(split.end - 1)
		}
		wg.Wait()
		close(resultsChan)

		results := make([]checkResult, 0, len(resultsChan))
		for result := range resultsChan {
			if result.err != nil {
				return 0, result.err
			}
			results = append(results, result)
		}
		sort.Slice(results, func(i, j int) bool { return results[i].checked < results[j].checked })

		if !results[len(results)-1].result {
			// The predicate is false over the entire range.
			return -1, nil
		}

		// Examine each split in order, looking for the split with the target. Every other result
		// represents the start of a split.
		for i := 0; i < len(results); i = i + 2 {
			start, end := results[i], results[i+1]
			if start.result {
				// If previous splits did not contain the target, then it must be the current start.
				return start.checked, nil
			}
			if end.result {
				// The target must be in [start.checked, end.checked].
				currentRange = intRange{start.checked, end.checked + 1}
				break
			}
		}
	}

	ok, err := s.check(currentRange.start)
	if err != nil {
		return 0, err
	}
	if !ok {
		return -1, nil
	}
	return currentRange.start, nil
}
