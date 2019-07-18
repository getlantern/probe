package probe

import (
	"bytes"
	"encoding/gob"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRandomizedProbeBaselineMarshaling(t *testing.T) {
	before, after := randomizedProbeBaseline{1.1, 2.2, 3.3}, randomizedProbeBaseline{}
	buf := new(bytes.Buffer)
	require.NoError(t, gob.NewEncoder(buf).Encode(before))
	require.NoError(t, gob.NewDecoder(buf).Decode(&after))
	require.Equal(t, before, after)
}
