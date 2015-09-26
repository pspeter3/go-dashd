package dashd

import (
	"fmt"
	"net"
	"net/http"
)

// Maker object.
type Maker struct {
	key string
}

// Create a Maker channel.
func NewMaker(key string) *Maker {
	return &Maker{key}
}

// Trigger IFTTT.
func (m *Maker) Trigger(event string) error {
	url := fmt.Sprintf("https://maker.ifttt.com/trigger/%s/with/key/%s", event, m.key)
	res, err := http.Get(url)
	defer res.Body.Close()
	return err
}

// Handle MAC addresses.
func (m *Maker) Serve(sources <-chan net.HardwareAddr) <-chan error {
	errors := make(chan error)
	go func() {
		for source := range sources {
			errors <- m.Trigger(source.String())
		}
	}()
	return errors
}
