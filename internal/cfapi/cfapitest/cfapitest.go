// Package cfapitest is an in-memory fake of the slice of the Cloudflare v4 API
// that internal/cfapi uses, for tests of the client and of the handlers built
// on it. It keeps tunnels, tunnel configurations, zones and DNS records in
// memory and answers in Cloudflare's {success, errors, result} envelope.
package cfapitest

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Account is the single account the fake serves.
const Account = "acc1"

// Token is the API token the fake accepts.
const Token = "test-api-token"

// Tunnel is a stored tunnel.
type Tunnel struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Status      string       `json:"status"`
	CreatedAt   string       `json:"created_at"`
	ConfigSrc   string       `json:"config_src"`
	Connections []Connection `json:"connections"`
	DeletedAt   *string      `json:"deleted_at"`
}

// Connection is a connector link.
type Connection struct {
	ID       string `json:"id"`
	ColoName string `json:"colo_name"`
	OriginIP string `json:"origin_ip"`
	OpenedAt string `json:"opened_at"`
}

// Zone is a stored zone.
type Zone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// Record is a stored DNS record.
type Record struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	ZoneID  string `json:"-"`
}

// Server is the fake. Mutate its exported state only before a request is in
// flight, or through the methods, which lock.
type Server struct {
	*httptest.Server

	mu      sync.Mutex
	Tunnels []*Tunnel
	Configs map[string]map[string]json.RawMessage // by tunnel ID
	Zones   []Zone
	Records []*Record
	// PerPage, when > 0, overrides the client's per_page so tests can force
	// multi-page results.
	PerPage int
	// Calls records "METHOD path" for every request that reached a handler.
	Calls []string
	seq   int
}

// New starts a fake Cloudflare API and stops it when the test ends.
func New(t *testing.T) *Server {
	t.Helper()
	s := &Server{Configs: map[string]map[string]json.RawMessage{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// AddTunnel stores a tunnel and returns it.
func (s *Server) AddTunnel(name, status string, conns int) *Tunnel {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	t := &Tunnel{ID: "tun-" + strconv.Itoa(s.seq), Name: name, Status: status, CreatedAt: "2026-11-01T10:00:00Z", ConfigSrc: "cloudflare"}
	for i := 0; i < conns; i++ {
		t.Connections = append(t.Connections, Connection{ID: "c" + strconv.Itoa(i), ColoName: "LHR", OriginIP: "203.0.113.7", OpenedAt: "2026-11-12T08:00:00Z"})
	}
	s.Tunnels = append(s.Tunnels, t)
	return t
}

// AddZone stores a zone and returns its ID.
func (s *Server) AddZone(name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	id := "zone-" + strconv.Itoa(s.seq)
	s.Zones = append(s.Zones, Zone{ID: id, Name: name, Status: "active"})
	return id
}

// AddRecord stores a DNS record.
func (s *Server) AddRecord(zoneID, name, typ, content string, proxied bool) *Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	r := &Record{ID: "rec-" + strconv.Itoa(s.seq), Name: name, Type: typ, Content: content, Proxied: proxied, ZoneID: zoneID}
	s.Records = append(s.Records, r)
	return r
}

// SetConfig stores a tunnel's configuration document (the value of "config").
func (s *Server) SetConfig(tunnelID, doc string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(doc), &m); err != nil {
		panic(err)
	}
	s.Configs[tunnelID] = m
}

// Config returns the stored configuration of a tunnel.
func (s *Server) Config(tunnelID string) map[string]json.RawMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Configs[tunnelID]
}

// RecordsFor returns a copy of the stored records.
func (s *Server) RecordsFor() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Record, 0, len(s.Records))
	for _, r := range s.Records {
		out = append(out, *r)
	}
	return out
}

// CallCount counts recorded calls whose "METHOD path" starts with prefix.
func (s *Server) CallCount(prefix string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.Calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func reply(w http.ResponseWriter, status int, result any, pages int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":     true,
		"errors":      []any{},
		"result":      result,
		"result_info": map[string]any{"page": 1, "total_pages": pages},
	})
}

func fail(w http.ResponseWriter, status, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": false,
		"errors":  []map[string]any{{"code": code, "message": msg}},
		"result":  nil,
	})
}

func page[T any](items []T, r *http.Request, forced int) ([]T, int) {
	per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if forced > 0 {
		per = forced
	}
	if per <= 0 {
		per = 50
	}
	pg, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if pg < 1 {
		pg = 1
	}
	pages := (len(items) + per - 1) / per
	if pages == 0 {
		pages = 1
	}
	lo := (pg - 1) * per
	if lo > len(items) {
		lo = len(items)
	}
	hi := lo + per
	if hi > len(items) {
		hi = len(items)
	}
	return items[lo:hi], pages
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Calls = append(s.Calls, r.Method+" "+r.URL.Path)

	if r.Header.Get("Authorization") != "Bearer "+Token {
		fail(w, http.StatusForbidden, 10000, "Authentication error")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case len(parts) == 1 && parts[0] == "accounts" && r.Method == http.MethodGet:
		reply(w, 200, []map[string]string{{"id": Account, "name": "Test Account"}}, 1)
	case len(parts) >= 3 && parts[0] == "accounts" && parts[2] == "cfd_tunnel":
		if parts[1] != Account {
			fail(w, http.StatusForbidden, 10000, "Authentication error")
			return
		}
		s.tunnels(w, r, parts[3:])
	case len(parts) == 1 && parts[0] == "zones" && r.Method == http.MethodGet:
		items, pages := page(s.Zones, r, s.PerPage)
		reply(w, 200, items, pages)
	case len(parts) >= 3 && parts[0] == "zones" && parts[2] == "dns_records":
		s.dns(w, r, parts[1], parts[3:])
	default:
		fail(w, http.StatusNotFound, 7003, "no route for "+r.Method+" "+r.URL.Path)
	}
}

func (s *Server) tunnel(id string) *Tunnel {
	for _, t := range s.Tunnels {
		if t.ID == id && t.DeletedAt == nil {
			return t
		}
	}
	return nil
}

func (s *Server) tunnels(w http.ResponseWriter, r *http.Request, rest []string) {
	switch {
	case len(rest) == 0 && r.Method == http.MethodGet:
		var live []*Tunnel
		for _, t := range s.Tunnels {
			if t.DeletedAt == nil {
				live = append(live, t)
			}
		}
		items, pages := page(live, r, s.PerPage)
		reply(w, 200, items, pages)
	case len(rest) == 0 && r.Method == http.MethodPost:
		var body struct {
			Name      string `json:"name"`
			ConfigSrc string `json:"config_src"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Name == "" {
			fail(w, http.StatusBadRequest, 1001, "tunnel name is required")
			return
		}
		s.seq++
		t := &Tunnel{ID: "tun-" + strconv.Itoa(s.seq), Name: body.Name, Status: "inactive", CreatedAt: "2026-11-12T09:00:00Z", ConfigSrc: body.ConfigSrc}
		s.Tunnels = append(s.Tunnels, t)
		reply(w, 200, t, 1)
	case len(rest) == 1 && r.Method == http.MethodGet:
		if t := s.tunnel(rest[0]); t != nil {
			reply(w, 200, t, 1)
			return
		}
		fail(w, http.StatusNotFound, 1003, "tunnel not found")
	case len(rest) == 1 && r.Method == http.MethodDelete:
		t := s.tunnel(rest[0])
		if t == nil {
			fail(w, http.StatusNotFound, 1003, "tunnel not found")
			return
		}
		if len(t.Connections) > 0 {
			fail(w, http.StatusBadRequest, 1022, "Cannot delete a tunnel with active connections")
			return
		}
		now := "2026-11-12T09:30:00Z"
		t.DeletedAt = &now
		reply(w, 200, t, 1)
	case len(rest) == 2 && rest[1] == "token" && r.Method == http.MethodGet:
		if s.tunnel(rest[0]) == nil {
			fail(w, http.StatusNotFound, 1003, "tunnel not found")
			return
		}
		doc, _ := json.Marshal(map[string]string{"a": Account, "t": rest[0], "s": "c2VjcmV0"})
		reply(w, 200, base64.StdEncoding.EncodeToString(doc), 1)
	case len(rest) == 2 && rest[1] == "configurations" && r.Method == http.MethodGet:
		if s.tunnel(rest[0]) == nil {
			fail(w, http.StatusNotFound, 1003, "tunnel not found")
			return
		}
		res := map[string]any{"tunnel_id": rest[0], "version": 1}
		if cfg, ok := s.Configs[rest[0]]; ok {
			res["config"] = cfg
		} else {
			res["config"] = nil
		}
		reply(w, 200, res, 1)
	case len(rest) == 2 && rest[1] == "configurations" && r.Method == http.MethodPut:
		if s.tunnel(rest[0]) == nil {
			fail(w, http.StatusNotFound, 1003, "tunnel not found")
			return
		}
		var body struct {
			Config map[string]json.RawMessage `json:"config"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Config == nil {
			fail(w, http.StatusBadRequest, 1001, "invalid config")
			return
		}
		s.Configs[rest[0]] = body.Config
		reply(w, 200, map[string]any{"tunnel_id": rest[0], "version": 2, "config": body.Config}, 1)
	default:
		fail(w, http.StatusNotFound, 7003, "no tunnel route")
	}
}

func (s *Server) dns(w http.ResponseWriter, r *http.Request, zoneID string, rest []string) {
	known := false
	for _, z := range s.Zones {
		if z.ID == zoneID {
			known = true
		}
	}
	if !known {
		fail(w, http.StatusNotFound, 7003, "zone not found")
		return
	}
	switch {
	case len(rest) == 0 && r.Method == http.MethodGet:
		q := r.URL.Query()
		var out []*Record
		for _, rec := range s.Records {
			if rec.ZoneID != zoneID {
				continue
			}
			if n := q.Get("name"); n != "" && !strings.EqualFold(rec.Name, n) {
				continue
			}
			if t := q.Get("type"); t != "" && rec.Type != t {
				continue
			}
			if c := q.Get("content"); c != "" && rec.Content != c {
				continue
			}
			out = append(out, rec)
		}
		items, pages := page(out, r, s.PerPage)
		reply(w, 200, items, pages)
	case len(rest) == 0 && r.Method == http.MethodPost:
		var body Record
		_ = json.NewDecoder(r.Body).Decode(&body)
		for _, rec := range s.Records {
			if rec.ZoneID == zoneID && strings.EqualFold(rec.Name, body.Name) && rec.Type == "CNAME" {
				fail(w, http.StatusBadRequest, 81053, "An A, AAAA, or CNAME record with that host already exists.")
				return
			}
		}
		s.seq++
		rec := &Record{ID: "rec-" + strconv.Itoa(s.seq), Name: body.Name, Type: body.Type, Content: body.Content, Proxied: body.Proxied, ZoneID: zoneID}
		s.Records = append(s.Records, rec)
		reply(w, 200, rec, 1)
	case len(rest) == 1 && r.Method == http.MethodPut:
		var body Record
		_ = json.NewDecoder(r.Body).Decode(&body)
		for _, rec := range s.Records {
			if rec.ID == rest[0] && rec.ZoneID == zoneID {
				rec.Type, rec.Name, rec.Content, rec.Proxied = body.Type, body.Name, body.Content, body.Proxied
				reply(w, 200, rec, 1)
				return
			}
		}
		fail(w, http.StatusNotFound, 81044, "Record does not exist.")
	case len(rest) == 1 && r.Method == http.MethodDelete:
		for i, rec := range s.Records {
			if rec.ID == rest[0] && rec.ZoneID == zoneID {
				s.Records = append(s.Records[:i], s.Records[i+1:]...)
				reply(w, 200, map[string]string{"id": rest[0]}, 1)
				return
			}
		}
		fail(w, http.StatusNotFound, 81044, "Record does not exist.")
	default:
		fail(w, http.StatusNotFound, 7003, "no dns route")
	}
}
