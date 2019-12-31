package openid

import (
        "context"
        "fmt"
        "net/http"
)

func ExampleNew() {
        ctx := context.Background()
        auth := openid.New(ctx, &openid.Config{
                Provider: "https://accounts.google.com",
                ClientID: "xxx.apps.googleusercontent.com",
        })
        http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
                user, err := auth.User(r)
                if err != nil {
                        auth.Redirect(w, r)
                        return
                }
                fmt.Fprintf(w, "Hello %v", user)
        })
}
