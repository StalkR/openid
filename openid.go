/*
Package openid implements OpenID Connect authentication.

The package uses the ID Token flow, as it conveniently stores the
user email address in the claims, so no further requests are required.
A temporary nonce cookie is established at the beginning and verified at the
end of the flow, protecting against login CSRF.
As the ID token is returned to the redirect URI in the fragment, a small
JavaScript is responsible for sending it to the server via POST.
The ID token is then verified and stored as-is in a session cookie of 1 year.
On future requests, the ID token is obtained and verified from the session
cookie, and the user email can be extracted.
Since the ID token expiration is typically only 1h, expiry is only verified
during authentication and not in subsequent requests.
The user email must be verified at the provider.

To use it:

1) Choose an identity provider, e.g. Google

2) Register an OAuth application at the provider

 - configure OAuth consent screen, e.g. at
   https://console.developers.google.com/apis/credentials/consent
 - create an OAuth Client ID credential of type Web, e.g. at
   https://console.developers.google.com/apis/credentials
 - for authorized redirect URIs add your origin + /auth/callback
 - create and copy the client ID, the client secret is not needed

3) Use the package

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
*/
package openid

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "log"
    "net/http"
    "net/url"
    "strings"

    oidc "github.com/coreos/go-oidc"
)

// Config configures the auth module.
type Config struct {
    Provider string
    ClientID string
}

const callback = "/auth/callback"

// New creates a new authentication module.
// It registers a handler at /auth/callback for the provider.
func New(ctx context.Context, config *Config) *Auth {
    provider, err := oidc.NewProvider(ctx, config.Provider)
    if err != nil {
        log.Fatal(err)
    }
    auth := &Auth{
        clientID: config.ClientID,
        provider: provider,
    }
    http.HandleFunc(callback, auth.handle)
    return auth
}

// Auth represents the auth module.
type Auth struct {
    clientID string
    provider *oidc.Provider
}

const (
    nonceCookie = "__Host-AuthNonce"
    tokenCookie = "__Host-AuthToken"
)

// Redirect redirects the user to the provider for authentication.
func (s *Auth) Redirect(w http.ResponseWriter, r *http.Request) {
    deleteCookie(w, tokenCookie)
    nonce := hex.EncodeToString(randBytes(20))
    const oneHour = 60 * 60
    setCookie(w, nonceCookie, nonce, oneHour)
    u := url.URL{
        Scheme: "https",
        Host:   r.Host,
        Path:   callback,
    }
    v := url.Values{
        "response_type": {"id_token"},
        "client_id":     {s.clientID},
        "redirect_uri":  {u.String()},
        "scope":         {"email"},
        "nonce":         {nonce},
    }
    authURL := s.provider.Endpoint().AuthURL
    sep := "?"
    if strings.Contains(authURL, "?") {
        sep = "&"
    }
    http.Redirect(w, r, authURL+sep+v.Encode(), http.StatusFound)
}

func (s *Auth) handle(w http.ResponseWriter, r *http.Request) {
    if r.Method == "GET" {
        fmt.Fprint(w, `<html><body><script>
let hash = window.location.hash.substr(1);
let fragments = hash.split('&').reduce((fragments, e) => {
    let parts = e.split('=');
    fragments[parts[0]] = parts[1];
    return fragments;
}, {});
let form = document.createElement('form');
form.method = 'POST';
form.action = '`+callback+`';
let input = document.createElement('input');
input.type = 'hidden';
input.name = 'id_token';
input.value = fragments['id_token'];
form.appendChild(input);
document.body.appendChild(form);
form.submit();
</script></body></html>`)
        return
    }
    const skipExpiry = false
    _, nonce, err := s.verify(r, r.FormValue("id_token"), skipExpiry)
    if err != nil {
        http.Error(w, "Invalid ID token: "+err.Error(), http.StatusInternalServerError)
        return
    }
    if c, err := r.Cookie(nonceCookie); err != nil || nonce != c.Value {
        http.Error(w, "Invalid nonce", http.StatusInternalServerError)
        return
    }
    deleteCookie(w, nonceCookie)
    const oneYear = 365 * 24 * 60 * 60
    setCookie(w, tokenCookie, r.FormValue("id_token"), oneYear)
    http.Redirect(w, r, "/", http.StatusFound)
}

// User returns the user email after verifying the id token cookie.
func (s *Auth) User(r *http.Request) (string, error) {
    c, err := r.Cookie(tokenCookie)
    if err != nil {
        return "", fmt.Errorf("no auth token cookie")
    }
    const skipExpiry = true
    email, _, err := s.verify(r, c.Value, skipExpiry)
    if err != nil {
        return "", fmt.Errorf("invalid ID token: %v", err)
    }
    return email, nil
}

func (s *Auth) verify(r *http.Request, token string, skipExpiry bool) (string, string, error) {
    config := &oidc.Config{ClientID: s.clientID}
    if skipExpiry {
        config.SkipExpiryCheck = true
    }
    idToken, err := s.provider.Verifier(config).Verify(r.Context(), token)
    if err != nil {
        return "", "", err
    }
    var claims struct {
        Email         string `json:"email"`
        EmailVerified bool   `json:"email_verified"`
    }
    if err := idToken.Claims(&claims); err != nil {
        return "", "", fmt.Errorf("claims: %v", err)
    }
    if !claims.EmailVerified {
        return "", "", fmt.Errorf("email not verified: %v", claims.Email)
    }
    return claims.Email, idToken.Nonce, nil
}

func setCookie(w http.ResponseWriter, name, value string, maxAge int) {
    http.SetCookie(w, &http.Cookie{
        Name:     name,
        Value:    value,
        Path:     "/",
        MaxAge:   maxAge,
        Secure:   true,
        HttpOnly: true,
        SameSite: http.SameSiteStrictMode,
    })
}

func deleteCookie(w http.ResponseWriter, name string) {
    setCookie(w, name, "", -1)
}

func randBytes(length int) []byte {
    b := make([]byte, length)
    if _, err := rand.Read(b); err != nil {
        panic(fmt.Sprintf("read rand failed: %v", err))
    }
    return b
}
