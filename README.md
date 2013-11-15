# securecookie
--
    import "github.com/andreadipersio/securecookie"

securecookie provide a go implementation of tornado (2.4) secure cookies.

## Usage

#### func  CreateSignedValue

```go
func CreateSignedValue(secret, name, value string, createdAt time.Time) string
```
CreateSignedValue signs and timestamps a string so it cannot be forged.

#### func  DecodeSignedValue

```go
func DecodeSignedValue(secret, name, signedValue string) (string, error)
```
DecodeSignedValue returns the given signed cookie if it validates, or error.

#### func  GetSecureCookie

```go
func GetSecureCookie(r *http.Response, secret, name string) (*http.Cookie, error)
```
GetSecureCookie returns the named cookie provided in the response or ErrNoCookie
if not found, or error if secure cookie value cannot be decoded. Secret should
be a long, random sequence of bytes

#### func  MustDecodeSignedValue

```go
func MustDecodeSignedValue(secret, name, signedValue string) string
```

#### func  SetSecureCookie

```go
func SetSecureCookie(w http.ResponseWriter, secret string, c *http.Cookie)
```
SetSecureCookie signs and timestamps a cookie so it cannot be forged. Secret
should be a long, random sequence of bytes to be used as the HMAC secret for the
signature. Secure cookies may contain arbitrary byte values, not just unicode
strings (unlike regular cookies)

#### func  SignCookie

```go
func SignCookie(c *http.Cookie, secret string)
```
SignCookie replace Value of cookie c with a signed string
