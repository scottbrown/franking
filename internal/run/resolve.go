package run

import (
	"context"
	"net"
	"sync"
	"time"

	"franking/internal/aggregate"
	"franking/internal/safe"
)

// The reverse DNS budget. These are the only network calls the tool makes,
// and only when -resolve is set.
const (
	lookupTimeout = 2 * time.Second
	lookupBudget  = 30 * time.Second
	lookupWorkers = 8
)

// resolveHosts does a PTR lookup for each source address. A PTR record is a
// string the address owner controls, so the answer is sanitized like any
// other untrusted string.
func resolveHosts(parent context.Context, sources []*aggregate.Source) {
	ctx, cancel := context.WithTimeout(parent, lookupBudget)
	defer cancel()

	resolver := net.DefaultResolver
	queue := make(chan *aggregate.Source)
	var wg sync.WaitGroup

	for range lookupWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for src := range queue {
				src.Host = lookup(ctx, resolver, src.IP)
			}
		}()
	}

	for _, src := range sources {
		if ctx.Err() != nil {
			break
		}
		if src.IP == safe.InvalidIP {
			continue
		}
		select {
		case queue <- src:
		case <-ctx.Done():
		}
	}
	close(queue)
	wg.Wait()
}

func lookup(parent context.Context, resolver *net.Resolver, ip string) string {
	if parent.Err() != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(parent, lookupTimeout)
	defer cancel()

	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return safe.Host(names[0])
}
