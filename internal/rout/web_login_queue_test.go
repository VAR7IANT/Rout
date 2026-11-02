package rout

import (
	"net/http"
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
