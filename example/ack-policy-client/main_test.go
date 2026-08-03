package main

import (
	"testing"

	quic "github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestParseACKPolicy(t *testing.T) {
	testCases := map[string]quic.ACKPolicy{
		"fixed2":   quic.ACKPolicyFixed2,
		"fixed10":  quic.ACKPolicyFixed10,
		"neqo":     quic.ACKPolicyNeqo,
		"chromium": quic.ACKPolicyChromium,
	}
	for name, expected := range testCases {
		actual, err := parseACKPolicy(name)
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	}
}

func TestParseACKPolicyRejectsLegacyAndUnknownNames(t *testing.T) {
	for _, name := range []string{"", "default", "quiche", "ack2", "fixed5"} {
		_, err := parseACKPolicy(name)
		require.EqualError(t, err, "invalid -ack-policy \""+name+"\"; valid values: fixed2, fixed10, neqo, chromium")
	}
}
