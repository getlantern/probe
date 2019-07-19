package probe

type minBinarySearch struct {
	predicate func(i int) (bool, error)
	memoized  map[int]bool
}

func (s *minBinarySearch) check(i int) (bool, error) {
	if v, ok := s.memoized[i]; ok {
		return v, nil
	}
	v, err := s.predicate(i)
	if err != nil {
		return false, err
	}
	s.memoized[i] = v
	return v, nil
}

// Returns the minimum integer in the range [start, end) for which the predicate is true. Assumes:
// 	- end > start
//	- start is > 0
//	- if predicate(i) is true, then predicate(n) is true for all n > i
//	- if predicate(i) is false, then preciate(n) is false for all n < i
// Returns -1 if the predicate is false over the entire range.
// Returns an error immediately if predicate returns an error.
func (s *minBinarySearch) search(start, end int) (int, error) {
	// Base Case 1: the predicate is always true.
	startTrue, err := s.check(start)
	if err != nil {
		return 0, err
	}
	if startTrue {
		return start, nil
	}

	// Base Case 2: the predicate is never true.
	endTrue, err := s.check(end - 1)
	if err != nil {
		return 0, err
	}
	if !endTrue {
		return -1, nil
	}

	// We recurse on either the upper half or the lower half.
	middle := ((end - start) / 2) + start
	middleTrue, err := s.check(middle)
	if err != nil {
		return 0, err
	}
	if !middleTrue {
		return s.search(middle+1, end)
	}
	lowerHalfResult, err := s.search(start, middle)
	if err != nil {
		return 0, err
	}
	if lowerHalfResult != -1 {
		return lowerHalfResult, nil
	}
	return middle, nil
}
