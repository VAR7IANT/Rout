package rout

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newNode(t *testing.T, taken ...int) Profile {
	t.Helper()
	p := fixture(t, "ss")
	p.Port = distinctFreePort(t, taken...)
	p.PublicPort = p.Port
	return p
}

// A commit built from a state that has since changed on disk is refused with
// errStateChanged, which callers recognise with errors.Is rather than by its text.
func TestCommitStaleStateReturnsErrStateChanged(t *testing.T) {
	a := testApp(t)
	old, e := a.Load()
	if e != nil {
		t.Fatal(e)
	}
	first := newNode(t)
	if e := a.Commit(old, replace(old, first), false); e != nil {
		t.Fatal(e)
	}
	e = a.Commit(old, replace(old, newNode(t, first.Port)), false)
	if !errors.Is(e, errStateChanged) {
		t.Fatalf("want errStateChanged, got %v", e)
	}
}

// webMutate rebuilds its change on a fresh state and succeeds when another operation
// changed the configuration between its load and its commit.
func TestWebMutateRetriesAfterConcurrentChange(t *testing.T) {
	a := testApp(t)
	other := newNode(t)
	mine := newNode(t, other.Port)
	calls := 0
	e := a.webMutate(func(old State) (State, error) {
		calls++
		if calls == 1 {
			cur, e := a.Load()
			if e != nil {
				return old, e
			}
			if e := a.Commit(cur, replace(cur, other), false); e != nil {
				return old, e
			}
		}
		return replace(old, mine), nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if calls != 2 {
		t.Fatalf("change built %d times, want 2", calls)
	}
	s, _ := a.Load()
	if len(s.Profiles) != 2 {
		t.Fatalf("want both nodes kept, got %d profiles", len(s.Profiles))
	}
}

// The panel answers a conflict that outlasted the retries with 409 "conflict", not with a
// generic 400, so the browser can tell it apart from a rejected request.
func TestWebStateChangedIsConflict(t *testing.T) {
	s := &WebServer{}
	for _, err := range []error{errStateChanged, fmt.Errorf("保存失败：%w", errStateChanged)} {
		rec := httptest.NewRecorder()
		s.writeError(rec, &reqCtx{lang: "en"}, err)
		if rec.Code != http.StatusConflict {
			t.Fatalf("%v: status %d, want 409", err, rec.Code)
		}
		var body struct {
			Error struct{ Code, Message string } `json:"error"`
		}
		if e := json.Unmarshal(rec.Body.Bytes(), &body); e != nil {
			t.Fatal(e)
		}
		if body.Error.Code != "conflict" {
			t.Fatalf("%v: code %q, want conflict", err, body.Error.Code)
		}
	}
	rec := httptest.NewRecorder()
	s.writeError(rec, &reqCtx{lang: "en"}, errStateChanged)
	if want := `"Configuration changed in another operation; reopen the menu"`; !strings.Contains(rec.Body.String(), want) {
		t.Fatalf("message not translated: %s", rec.Body.String())
	}
}
