package auth

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	cases := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr error
	}{
		{
			name:    "no authorization header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed authorization header missing apiKey prefix",
			headers: http.Header{
				"Authorization": []string{"missing key"},
			},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "malformed authorization header with only one part",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "valid header",
			headers: http.Header{
				"Authorization": []string{"ApiKey someRand0Key"},
			},
			wantKey: "Rand0Key",
			wantErr: nil,
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("Test Case %v", i), func(t *testing.T) {

			actualKey, actualErr := GetAPIKey(c.headers)
			if actualKey != c.wantKey {
				t.Errorf("expected key: %v, got key: %v\n", c.wantKey, actualKey)
				t.Fail()

			}

			if c.wantErr != nil {
				if actualErr == nil || c.wantErr.Error() != actualErr.Error() {
					t.Errorf("expected error: %v, got error: %v\n", c.wantErr, actualErr)
					t.Fail()
				}
			} else if actualErr != nil {
				t.Errorf("unexpected error: %v\n", actualErr)
				t.Fail()

			}
		})
	}

}
