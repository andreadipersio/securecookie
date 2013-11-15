// Copyright 2013 Andrea Di Persio. All rights reserved.
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.
//
// Author: Andrea Di Persio <andrea.dipersio@gmail.com>

// securecookie provide a go implementation of tornado (2.4) secure cookies.
package securecookie

import (
    "fmt"
    "bytes"
    "time"
    "crypto/sha1"
    "crypto/hmac"
    "encoding/hex"
    "encoding/base64"
    "strconv"
    "strings"
    "net/http"
)

type withCookie interface {
    Cookies() []*http.Cookie
}

func cookieIsExpired (cookieTime time.Time) bool {
    return cookieTime.Before(time.Now().AddDate(0, 0, -31))
}

func cookieIsFromFuture(cookieTime time.Time) bool {
    return cookieTime.After(time.Now().AddDate(0, 0, 31))
}

func cookieIsTampered(timestamp []byte) bool {
    return bytes.HasPrefix(timestamp, []byte("0"))
}

func checkTimestamp(bTimestamp []byte) error {
    var timestamp int64

    if t, err := strconv.ParseInt(string(bTimestamp), 0, 64); err != nil {
        return fmt.Errorf("Invalid timestamp: %v, got error: %s",
                          bTimestamp, err)
    } else {
        timestamp = t
    }

    cookieTime := time.Unix(timestamp, 0)

    if cookieIsExpired(cookieTime) {
        return fmt.Errorf("Expired Cookie")
    }

    if cookieIsFromFuture(cookieTime) {
        return fmt.Errorf("Cookie timestamp is in the future," +
                          "possible tampering")
    }

    if cookieIsTampered(bTimestamp) {
        return fmt.Errorf("Tampered cookie")
    }

    return nil
}

// DecodeSignedValue returns the given signed cookie if it validates, or error.
func DecodeSignedValue(secret, name, signedValue string) (string, error) {
    var decodedValue string

    if signedValue == "" {
        return "", fmt.Errorf("Signed value is empty")
    }

    parts := bytes.Split([]byte(signedValue),[]byte("|"))

    if len(parts) != 3 {
        return "", fmt.Errorf("Incomplete signed value")
    }

    value := parts[0]
    timestamp := parts[1]
    signature := parts[2]

    newSignature := createSignature(secret, []byte(name), value, timestamp)

    if !bytes.Equal(signature, newSignature) {
        return "", fmt.Errorf("Invalid signature")
    }

    if err := checkTimestamp(timestamp); err != nil {
        return "", err
    }

    if data, err := base64.URLEncoding.DecodeString(string(value)); err == nil {
        decodedValue = string(data)
    }

    return decodedValue, nil
}

func MustDecodeSignedValue(secret, name, signedValue string) string {
    v, err := DecodeSignedValue(secret, name, signedValue)

    if err != nil {
        panic(err)
    }

    return v
}

func createSignature(secret string, parts ...[]byte) []byte {
    h := hmac.New(sha1.New, []byte(secret))

    for _, x := range parts {
        h.Write(x)
    }

    hexDigest := make([]byte, 64)
    hex.Encode(hexDigest, h.Sum(nil))

    return hexDigest[:bytes.Index(hexDigest, []byte("\000"))]
}

// CreateSignedValue signs and timestamps a string so it cannot be forged.
func CreateSignedValue(secret, name, value string, createdAt time.Time) string {
    ts := fmt.Sprint(createdAt.Unix())

    b64Value := base64.URLEncoding.EncodeToString([]byte(value))

    signature := createSignature(secret,
                                 []byte(name),
                                 []byte(b64Value),
                                 []byte(ts))

    signedValue := strings.Join([]string{b64Value, ts, fmt.Sprintf("%s", signature)}, "|")

    return signedValue
}

func SignCookie(c *http.Cookie, secret string) {
    c.Value = CreateSignedValue(secret, c.Name, c.Value, time.Now())
}

// SetSecureCookie signs and timestamps a cookie so it cannot be forged.
// Secret should be a long, random sequence of bytes
// to be used as the HMAC secret for the signature.
// Secure cookies may contain arbitrary byte values, not just unicode
// strings (unlike regular cookies)
func SetSecureCookie(w http.ResponseWriter, secret string, c *http.Cookie) {
    SignCookie(c, secret)

    http.SetCookie(w, c)
}

// GetSecureCookie returns the named cookie provided in the response or ErrNoCookie if not found,
// or error if secure cookie value cannot be decoded.
// Secret should be a long, random sequence of bytes
func GetSecureCookie(r withCookie, secret, name string) (*http.Cookie, error) {
    var c *http.Cookie

    for _, x := range r.Cookies() {
        if x.Name == name {
            c = x
            break
        }
    }

    if c == nil {
        return nil, http.ErrNoCookie
    }

    if v, err := DecodeSignedValue(secret, c.Name, c.Value); err != nil {
        return nil, err
    } else {
        c.Value = v
    }

    return c, nil
}
