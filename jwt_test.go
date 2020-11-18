package jwt_rewrite

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJwtVerify(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// 00000000000000000000000000000000000000000000
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"alive": true}`)

		auth := r.Header.Get("Authorization")
		if auth != "Bearer eyJhbGciOiAiSFMyNTYiLCJ0eXAiOiAiSldUIgp9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InJvdGVtIGJhciIsImlhdCI6MTcxNjIzOTAyMn0.QbbRxpej1f5dpbmKkISG2kvY8bTEWXED7nZNwPPuyhE" {
			fmt.Println(auth)
			t.Fatalf("Error in JWT")
		}

	})
	c := CreateConfig()
	c.VerifyHash = "HS512"
	c.VerifySecret = "00000000000000000000000000000000000000000000"
	c.SignSecret = "11111111111111111111111111111111111111111111"
	s, _ := New(nil, handler, c, "test")

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InJvdGVtIGJhciIsImlhdCI6MTcxNjIzOTAyMn0.E6YQwrg78wFCDHYJsQDMQp8uDtMRTuORv-UPMii8qH1iS11FgdAcKm-8XdgmGLXS8jNOD_xxNXq_A5mde5T_FQ")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	resp := w.Result()

	fmt.Println(resp.StatusCode)
	//fmt.Println(req.Header.Get("Authorization"))

	// Output:
	// 200
}
