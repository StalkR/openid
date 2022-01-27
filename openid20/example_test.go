package openid20_test

import (
        "fmt"
        "net/http"

        "github.com/StalkR/openid/openid20"
)

func ExampleNew() {
        auth := openid20.New("https://steamcommunity.com/openid/login", "https://example.com/auth")
        http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
                http.Redirect(w, r, auth.RedirectURL(), http.StatusSeeOther)
        })
        http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
                user, err := auth.Verify(r)
                if err != nil {
                        http.Error(w, err.Error(), http.StatusForbidden)
                        return
                }
                fmt.Fprintf(w, "hello %v", user)
        })

}
