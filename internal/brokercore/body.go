package brokercore

import (
	"bytes"
	"errors"
	"io"
	"net/http"
)

// MaterializeRequestBody buffers body so the request has a real Content-Length; callers must cap it with http.MaxBytesReader first.
func MaterializeRequestBody(body io.ReadCloser) (io.ReadCloser, int64, error) {
	if body == nil || body == http.NoBody {
		return http.NoBody, 0, nil
	}
	defer func() { _ = body.Close() }()

	data, err := io.ReadAll(body)
	if err != nil {
		return nil, 0, err
	}
	if len(data) == 0 {
		return http.NoBody, 0, nil
	}
	return io.NopCloser(bytes.NewReader(data)), int64(len(data)), nil
}

// RequestBodyErrorCode maps a MaterializeRequestBody error to a proxy status and error code.
func RequestBodyErrorCode(err error) (status int, code string) {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		return http.StatusRequestEntityTooLarge, "request_too_large"
	}
	return http.StatusBadRequest, "request_read_error"
}
