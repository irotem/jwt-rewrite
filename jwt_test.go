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
		if auth != "Bearer eyJhbGciOiAiSFMyNTYiLCJ0eXAiOiAiSldUIgp9.eyJpc3MiOiJ0ZXN0IiwiZXhwIjoxNjA1NzgxOTM1LCJmaXJzdF9uYW1lIjoiUm90ZW0iLCJlbWFpbCI6InJvdGVtYkBnbWFpbC5jb20iLCJjdXN0b20tY2xhaW1zIjogewogICAgIngtdXNlci1pZCI6ICJyb3RlbWJAZ21haWwuY29tIgp9fQ.K-sMmui2g8PkWePvFu3zpJX8WnW5iQWTPuxvqgn94oE" {
			fmt.Println(auth)
			t.Fatalf("Error in JWT")
		}

	})
	c := CreateConfig()
	c.VerifyHash = "HS512"
	c.VerifySecret = "11111111111111111111111111111111111111110000"
	c.SignSecret = "11111111111111111111111111111111111111111111"
	c.SignHash = "HS256"
	c.CopyClaims["email"] = "ImN1c3RvbS1jbGFpbXMiOiB7CiAgICAieC11c2VyLWlkIjogIiRlbWFpbCQiCn0="

	s, _ := New(nil, handler, c, "test")

	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0IiwiZXhwIjoxNjA1NzgxOTM1LCJmaXJzdF9uYW1lIjoiUm90ZW0iLCJlbWFpbCI6InJvdGVtYkBnbWFpbC5jb20ifQ.-qHmcwCUjaScLD5ANZAEHeAo-BdPLmfXMYvDApMR2IdZqvJKRfadxfnEjkkOYI6TiuI1XgAFjElEaA9v5usnDw")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	resp := w.Result()

	fmt.Println(resp.StatusCode)

	// Output:
	// 200
}
