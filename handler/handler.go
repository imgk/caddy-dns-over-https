package handler

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("dns_over_https", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		mod := &Handler{}
		err := mod.UnmarshalCaddyfile(h.Dispenser)
		return mod, err
	})
}

// Handler implements an HTTP handler that ...
type Handler struct {
	// Upstream is ...
	Upstream string `json:"upstream"`

	upstream upstream.Upstream
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.dns_over_https",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision implements caddy.Provisioner.
func (m *Handler) Provision(ctx caddy.Context) error {
	err := error(nil)
	m.upstream, err = upstream.AddressToUpstream(m.Upstream, nil)
	return err
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	req, code := func(rr *http.Request) (*dns.Msg, int) {
		buf := []byte{}
		err := error(nil)

		switch rr.Method {
		case http.MethodGet:
			dnsParam := rr.URL.Query().Get("dns")
			buf, err = base64.RawURLEncoding.DecodeString(dnsParam)
			if len(buf) == 0 || err != nil {
				return nil, http.StatusBadRequest
			}
		case http.MethodPost:
			contentType := rr.Header.Get("Content-Type")
			if contentType != "application/dns-message" {
				return nil, http.StatusUnsupportedMediaType
			}

			buf, err = io.ReadAll(rr.Body)
			if err != nil {
				return nil, http.StatusBadRequest
			}
		default:
			return nil, http.StatusMethodNotAllowed
		}

		req := &dns.Msg{}
		if err = req.Unpack(buf); err != nil {
			return nil, http.StatusBadRequest
		}

		return req, http.StatusOK
	}(r)
	if code != http.StatusOK {
		return next.ServeHTTP(w, r)
	}

	resp, err := m.upstream.Exchange(req)
	if err != nil {
		return fmt.Errorf("resolve dns error: %w", err)
	}

	w.Header().Set("Content-Type", "application/dns-message")
	bb, err := resp.Pack()
	if err != nil {
		return fmt.Errorf("pack dns message error: %w", err)
	}
	w.Write(bb)

	return nil
}

// UnmarshalCaddyfile unmarshals Caddyfile tokens into h.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.ArgErr()
	}
	args := d.RemainingArgs()
	if len(args) > 0 {
		return d.ArgErr()
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		subdirective := d.Val()
		switch subdirective {
		case "upstream":
			args := d.RemainingArgs()
			if len(args) < 1 {
				return d.ArgErr()
			}
			h.Upstream = args[0]
		}
	}
	return nil
}

// CleanUp is ...
func (m *Handler) Cleanup() error {
	return m.upstream.Close()
}

// Interface guards
var (
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
