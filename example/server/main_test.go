package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGeneratedBytesEndpoint(t *testing.T) {
	recorder := httptest.NewRecorder()
	setupHandler("").ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/bytes/32", nil))
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, "32", recorder.Header().Get("Content-Length"))
	require.Equal(t, generatePRData(32), recorder.Body.Bytes())
}

func TestGeneratedBytesEndpointRejectsInvalidRequests(t *testing.T) {
	testCases := []struct {
		method string
		path   string
		status int
	}{
		{method: http.MethodPost, path: "/bytes/32", status: http.StatusMethodNotAllowed},
		{method: http.MethodGet, path: "/bytes/", status: http.StatusBadRequest},
		{method: http.MethodGet, path: "/bytes/0", status: http.StatusBadRequest},
		{method: http.MethodGet, path: "/bytes/1073741825", status: http.StatusBadRequest},
	}
	for _, tc := range testCases {
		recorder := httptest.NewRecorder()
		setupHandler("").ServeHTTP(recorder, httptest.NewRequest(tc.method, tc.path, nil))
		require.Equal(t, tc.status, recorder.Code)
	}
}
