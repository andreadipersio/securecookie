package securecookie

import (
    "fmt"
    "time"
    "testing"
    "crypto/hmac"
    "net/http"
    "strings"
    "encoding/hex"
)

var (
    secret string = "sN?^WvQiOkv)QXhQwQZ>JH!YY/q(v%TY"
    now = time.Now()
)

func TestCreateSignature(t *testing.T) {
    errStr := "Function return different result with the same parameters!"

    a := createSignature(secret, []byte("foo"), []byte("bar"))
    b := a

    if !hmac.Equal(a, b) {
        t.Errorf(errStr)
    }

    c := createSignature(secret, []byte("foo"), []byte("baz"))

    if hmac.Equal(a, c) {
        t.Errorf(errStr)
    }
}

func TestCreateSignedValue(t *testing.T) {
    var tsSeconds int64 = 1371237542
    expected := fmt.Sprintf("NzA2NDQ2NzMw|%v|334de90e34d9e1ffab881002dc90d2b8b2614333", tsSeconds)

    name := "oauth_user_id"
    rawValue := "706446730"

    ts := time.Unix(tsSeconds, 0)

    signedValue := CreateSignedValue(secret, name, rawValue, ts)

    if signedValue != expected {
        t.Errorf("Got %s (%v) --- Expected %s (%v)", signedValue, len(signedValue),
                                                     expected, len(expected))
    }
}

func TestDecodeSignedValue(t *testing.T) {
    sign := func(name, value string) string {
        return CreateSignedValue(secret, name, value, now)
    }

    decode := func(name, signedValue string) string {
        return MustDecodeSignedValue(secret, name, signedValue)
    }

    xs := []struct {
        name, value string
    } {
        {"walter", "white"},
        {"jesse", "pinkman"},
        {"", ""},
    }

    for _, x := range xs {
        signedVal := sign(x.name, x.value)
        decodedVal := decode(x.name, signedVal)

        if decodedVal != x.value {
            t.Errorf("Got %v (len %v) --- Expected %v (len %v)",
                     decodedVal, len(decodedVal), x.value, len(x.value))
        }
    }
}

func TestSecureCookie(t *testing.T) {
    server := func() {
        http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
            c := &http.Cookie{
                Name: "foo",
                Value: "bar",
            }

            SetSecureCookie(w, secret, c)

            fmt.Fprintf(w, "Stay out of my territory.")
        })

        http.ListenAndServe(":8383", nil)
    }

    go server()

    resp, err := http.Get("http://localhost:8383")

    if err != nil {
        t.Errorf("Cannot connect to test server: %v", err)
    }

    t.Logf("Response Header: %v", resp.Header)
    t.Logf("Response Cookies: %v", resp.Cookies())

    if c, err := GetSecureCookie(resp, secret, "foo"); err != nil {
        t.Errorf("%v", err)
    } else {
        if c.Value != "bar" {
            t.Errorf("Got %v --- Expected %v", c.Value, "bar")
        }
    }
}

func TestSignCookie(t *testing.T) {
    c := &http.Cookie{
        Name: "foo",
        Value: "foobar",
    }

    SignCookie(c, secret)

    if c.Value == "foobar" {
        t.Errorf("SignCookie Failed")
    }
}

func TestCookieTampering(t *testing.T) {
    // this string base64-encodes to '12345678'
    initialValue := "d76df8e7aefc"
    clearValue := "12345678"

    binValue, cannotDecode := hex.DecodeString(initialValue)

    if cannotDecode != nil {
        t.Errorf("Cannot Decode string %v", initialValue)
    }

    c := &http.Cookie{
        Name: "foo",
        Value: string(binValue),
    }

    SignCookie(c, secret)

    parts := strings.Split(c.Value, "|")

    if len(parts) != 3 {
        t.Errorf("Invalid cookie")
    }

    timestamp, sig := parts[1], parts[2]

    tests := []func() string{
        func() string {
            _sig := createSignature(
                secret,
                []byte("foo"),
                []byte(clearValue),
                []byte(timestamp),
            )

            return string(_sig)
        },

        // shifting digits from payload to timestamp doesn't alter signature
        // (this is not desirable behavior, just confirming that that's how it
        // works)
        func() string {
            _sig := createSignature(
                secret,
                []byte("foo"),
                []byte("1234"),
                []byte(strings.Join([]string{"5678", timestamp}, "")),
            )

            return string(_sig)
        },
    }

    for _, f := range tests {
        if _sig := f(); _sig != sig {
            t.Errorf("Invalid signature, Expected %v (len %v) --- Got %v (len %v)", sig, len(sig), _sig, len(_sig))
        }
    }

    tamperedValue := fmt.Sprintf("1234|5678%v|%v", timestamp, sig)

    if _, err := DecodeSignedValue(secret, "foo", tamperedValue); err == nil {
        t.Errorf("Tampered cookie should be rejected!")
    }
}
