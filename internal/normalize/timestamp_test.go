package normalize

import (
	"testing"

	"timeline/internal/domain"
)

func TestTimestampNormalization(t *testing.T) {
	ns, precision := UnixMillisToTimestampNS(1715025600123)
	if ns != 1715025600123000000 {
		t.Fatalf("UnixMillisToTimestampNS = %d", ns)
	}
	if precision != domain.TimestampPrecisionMillisecond {
		t.Fatalf("precision = %q", precision)
	}

	rfcNS, rfcPrecision, err := RFC3339ToTimestampNS("2024-05-06T20:00:00.123456789Z")
	if err != nil {
		t.Fatalf("RFC3339ToTimestampNS error: %v", err)
	}
	if rfcNS != 1715025600123456789 {
		t.Fatalf("RFC3339ToTimestampNS = %d", rfcNS)
	}
	if rfcPrecision != domain.TimestampPrecisionNanosecond {
		t.Fatalf("RFC3339 precision = %q", rfcPrecision)
	}
}
