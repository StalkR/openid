/*
Package openid20 implements simplistic Open ID 2.0 support.

Open ID 2.0 is obsolete and replaced by OpenID Connect but some providers still
use it, e.g. Steam.

Simplification choices of this library:
- it does not verify nonce reuse
  - the spec requires it but it's a terrible stateful idea requiring storage
  - you can replay identification, not a problem unless the return URL leaks
  - they expire after 1 minute anyway
- it does not verify discover information
  - we're only using openid.claimed_id property
  - spec says we should verify it can assert it, but it's the basic one
  - if the server is malicious it can lie on the discover anyway
  - avoids extra discover requests and caching of response
- it does not verify return_to scheme matches
  - because server itself doesn't know, e.g. if behind a reverse proxy
  - it's signed by the openid server anyway

Another potential problem with Open ID 2.0 spec is login xsrf, but it's easy
enough to mitigate in applications, if that's something you're concerned about:
- before redirecting: generate a nonce, set it as cookie and append it to return_to
- on verify: compare the nonce in cookie and URL

For a spec compliant but heavier library see https://github.com/yohcop/openid-go.
*/
package openid20

import (
  "errors"
  "fmt"
  "io/ioutil"
  "net/http"
  "net/url"
  "strings"
  "time"
)

// RedirectURL builds a redirect URL to login with the provider.
func RedirectURL(endpoint, returnTo string) string {
  v := url.Values{}
  v.Add("openid.ns", "http://specs.openid.net/auth/2.0")
  v.Add("openid.mode", "checkid_setup")
  v.Add("openid.return_to", returnTo)
  v.Add("openid.realm", realm(returnTo))
  v.Add("openid.claimed_id", "http://specs.openid.net/auth/2.0/identifier_select")
  v.Add("openid.identity", "http://specs.openid.net/auth/2.0/identifier_select")
  v.Add("openid.ns.sreg", "http://openid.net/extensions/sreg/1.1")
  querySeparator := "?"
  if strings.Contains(endpoint, "?") {
    querySeparator = "&"
  }
  return endpoint + querySeparator + v.Encode()
}

func realm(uri string) string {
  u, err := url.Parse(uri)
  if err != nil {
    panic(err)
  }
  return (&url.URL{Scheme: u.Scheme, Host: u.Host}).String()
}

// Verify verifies the return URL after a login and returns the openid.claimed_id.
func Verify(r *http.Request) (string, error) {
  if err := verifySignedFields(r); err != nil {
    return "", err
  }
  if err := verifySignature(r); err != nil {
    return "", err
  }
  if err := verifyReturnTo(r); err != nil {
    return "", err
  }
  if err := verifyNonce(r); err != nil {
    return "", err
  }
  return r.URL.Query().Get("openid.claimed_id"), nil
}

func verifySignedFields(r *http.Request) error {
  v := r.URL.Query()
  ok := map[string]bool{
    "op_endpoint":    false,
    "return_to":      false,
    "response_nonce": false,
    "assoc_handle":   false,
    "claimed_id":     v.Get("openid.claimed_id") == "",
    "identity":       v.Get("openid.identity") == "",
  }
  signed := strings.Split(v.Get("openid.signed"), ",")
  for _, sf := range signed {
    ok[sf] = true
  }
  for k, v := range ok {
    if !v {
      return fmt.Errorf("%v must be signed but isn't", k)
    }
  }
  return nil
}

func verifySignature(r *http.Request) error {
  v := r.URL.Query()
  params := url.Values{}
  params.Add("openid.mode", "check_authentication")
  for k, vs := range v {
    if k == "openid.mode" {
      continue
    }
    for _, e := range vs {
      params.Add(k, e)
    }
  }
  resp, err := http.PostForm(v.Get("openid.op_endpoint"), params)
  if err != nil {
    return err
  }
  defer resp.Body.Close()
  content, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    return err
  }
  isValid := false
  nsValid := false
  for _, l := range strings.Split(string(content), "\n") {
    if l == "is_valid:true" {
      isValid = true
    } else if l == "ns:http://specs.openid.net/auth/2.0" {
      nsValid = true
    }
  }
  if !isValid || !nsValid {
    return fmt.Errorf("could not verify assertion")
  }
  return nil
}

func verifyReturnTo(r *http.Request) error {
  v := r.URL.Query()
  returnTo, err := url.Parse(v.Get("openid.return_to"))
  if err != nil {
    return err
  }
  // not verifying scheme because server doesn't know (e.g. reverse proxy)
  if r.Host != returnTo.Host ||
    r.URL.Path != returnTo.Path {
    return fmt.Errorf("scheme, host or path doesn't match return_to URL")
  }
  // any param in return_to must also be present in v
  wantValues := returnTo.Query()
  for k := range wantValues {
    want := wantValues.Get(k)
    if got := v.Get(k); got != want {
      return fmt.Errorf("URL query param mismatch: got %v, want %v", got, want)
    }
  }
  return nil
}

func verifyNonce(r *http.Request) error {
  nonce := r.URL.Query().Get("openid.response_nonce")
  if len(nonce) < 20 || len(nonce) > 256 {
    return errors.New("invalid nonce")
  }
  ts, err := time.Parse(time.RFC3339, nonce[:20])
  if err != nil {
    return err
  }
  if ts.Add(time.Minute).Before(time.Now()) {
    return fmt.Errorf("nonce too old: %v", ts)
  }
  // note: by choice, not verifying nonce reuse
  return nil
}
