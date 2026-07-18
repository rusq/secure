package secure

import "errors"

var (
	ErrInvalidEnvelope    = errors.New("secure: invalid envelope")
	ErrAuthentication     = errors.New("secure: authentication failed")
	ErrUnsupportedVersion = errors.New("secure: unsupported envelope version")
	ErrLimitExceeded      = errors.New("secure: configured limit exceeded")
	ErrTruncated          = errors.New("secure: encrypted stream truncated")
	ErrUnconfigured       = errors.New("secure: value is not configured")
)
