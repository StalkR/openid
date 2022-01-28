package openid20_test

import (
        "fmt"
        "net/http"

        "github.com/StalkR/openid/openid20"
)

func ExampleNew() {
        const endpoint = "https://steamcommunity.com/openid/login"
        const returnTo = "https://example.com/auth"
        http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
                http.Redirect(w, r, openid20.RedirectURL(endpoint, returnTo), http.StatusSeeOther)
        })
        http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
                user, err := openid20.Verify(r)
                if err != nil {
                        http.Error(w, err.Error(), http.StatusForbidden)
                        return
                }
                fmt.Fprintf(w, "hello %v", user)
        })

}
