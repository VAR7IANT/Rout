package rout

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// Requests that queued for a hashing slot before a lockout was reached must not each get a
// password guess afterwards.
func TestLoginQueuedRequestsRespectLockoutEstablishedWhileWaiting(t *testing.T) {
	env := newWebEnv(t)
	env.ws.loginSem = make(chan struct{}, 1)
	env.ws.loginSem <- struct{}{} // the only hashing slot is busy

	const peer = "203.0.113.77:4000"
	const ip = "203.0.113.77"
	codes := make(chan int, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := env.anon().do("POST", "/api/login", map[string]string{"password": "wrong-guess"}, withPeer(peer))
			codes <- w.Code
		}()
	}
	// Give them time to pass the first check and block on the slot, then lock the client out
	// the way earlier failures would have.
	time.Sleep(300 * time.Millisecond)
	for i := 0; i < webLoginMaxFails; i++ {
		env.ws.limiter.failure(ip)
	}
	if ok, _ := env.ws.limiter.check(ip); ok {
		t.Fatal("setup: client is not locked out")
	}
	<-env.ws.loginSem // release the slot
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != http.StatusTooManyRequests {
			t.Fatalf("a queued request was evaluated after the lockout: status %d", code)
		}
	}
}

// A login that was waiting for a hashing slot while `rout web passwd` ran must not end with a
// session for the password that was just replaced.
func TestLoginDoesNotOutliveAPasswordChange(t *testing.T) {
	env := newWebEnv(t)
	env.ws.loginSem = make(chan struct{}, 1)
	env.ws.loginSem <- struct{}{}

	type result struct {
		code   int
		cookie string
	}
	done := make(chan result, 1)
	go func() {
		w := env.anon().do("POST", "/api/login", map[string]string{"password": webTestPassword}, withPeer("203.0.113.5:1"))
		done <- result{w.Code, w.Header().Get("Set-Cookie")}
	}()
	time.Sleep(300 * time.Millisecond) // the request has read the old configuration and waits
	env.clock.advance(time.Second)
	if e := env.a.SetWebPassword("a-brand-new-password-123"); e != nil {
		t.Fatal(e)
	}
	env.ws.invalidateConfig()
	<-env.ws.loginSem
	r := <-done
	if r.code == http.StatusOK || r.cookie != "" {
		t.Fatalf("a session was issued for the replaced password: status %d cookie %q", r.code, r.cookie)
	}
	if n := len(env.ws.sessions.list()); n != 0 {
		t.Fatalf("%d sessions exist", n)
	}
	// The new password works.
	if w := env.anon().do("POST", "/api/login", map[string]string{"password": "a-brand-new-password-123"}); w.Code != http.StatusOK {
		t.Fatalf("new password refused: %d", w.Code)
	}
}

// A ':' in the user name used to shift part of it into the password silently.
func TestExitUsernameWithColonIsRejected(t *testing.T) {
	env := newWebEnv(t)
	c := env.login()
	w := c.do("POST", "/api/exits", map[string]any{"name": "colon", "protocol": "socks5", "host": "198.51.100.9", "port": 1080, "username": "alice:team", "password": "secret"})
	if w.Code != http.StatusBadRequest && w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	w = c.do("GET", "/api/exits", nil)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "colon") {
		t.Fatalf("the exit was stored: %s", w.Body.String())
	}
}

func TestExitEditCannotIntroduceAColonInTheUsername(t *testing.T) {
	env := newWebEnv(t)
	c := env.login()
	w := c.do("POST", "/api/exits", map[string]any{"name": "ok", "protocol": "socks5", "host": "198.51.100.9", "port": 1080, "username": "alice", "password": "secret"})
	if w.Code != http.StatusOK {
		t.Fatalf("setup: %d %s", w.Code, w.Body.String())
	}
	id := jsonOf(t, w)["exit"].(map[string]any)["id"].(string)
	if w = c.do("PATCH", "/api/exits/"+id, map[string]any{"username": "alice:team"}); w.Code != http.StatusBadRequest && w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("edit accepted: %s", w.Body.String())
	}
}
