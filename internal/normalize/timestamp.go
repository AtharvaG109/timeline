package normalize

import (
	"fmt"
	"time"

	"timeline/internal/domain"
)

func UnixSecondsToTimestampNS(value int64) (int64, domain.TimestampPrecision) {
	return value * int64(time.Second), domain.TimestampPrecisionSecond
}

func UnixMillisToTimestampNS(value int64) (int64, domain.TimestampPrecision) {
	return value * int64(time.Millisecond), domain.TimestampPrecisionMillisecond
}

func RFC3339ToTimestampNS(value string) (int64, domain.TimestampPrecision, error) {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return 0, domain.TimestampPrecisionUnknown, fmt.Errorf("parse RFC3339 timestamp: %w", err)
	}
	return t.UTC().UnixNano(), domain.TimestampPrecisionNanosecond, nil
}
