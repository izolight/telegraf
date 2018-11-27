package wireguard

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/filter"
	"github.com/influxdata/telegraf/internal"
	"os/exec"
	"strings"
	"time"
)

type runner func(cmdName string, Timeout internal.Duration, UseSudo bool) (*bytes.Buffer, error)

// Used to store config
type Wireguard struct {
	Binary			string
	Timeout 		internal.Duration
	UseSudo 		bool
	InterfaceAsTag	bool
	PeerAsTag		bool

	filter	filter.Filter
	run		runner
}

var defaultBinary = "/usr/bin/wg"
var defaultTimeout = internal.Duration{Duration: time.Second}

var sampleConfig = `
  ## If running as a restricted user you can prepend sudo for additional access:
  # use_sudo = false

  ## The default location of the wg binary can be overridden with:
  # binary = "/usr/bin/wg"

  ## The default timeout of 1s can be overriden with:
  # timeout = "1s"
`

func (s *Wireguard) Description() string {
	return "A plugin to collect stats from the Wireguard VPN"
}

func (s *Wireguard) SampleConfig() string {
	return sampleConfig
}

func wireguardRunner(cmdName string, Timeout internal.Duration, UseSudo bool) (*bytes.Buffer, error) {
	cmdArgs := []string{"show"}

	cmd := exec.Command(cmdName, cmdArgs...)

	if UseSudo {
		cmdArgs = append([]string{cmdName}, cmdArgs...)
		cmd = exec.Command("sudo", cmdArgs...)
	}

	var out bytes.Buffer
	cmd.Stdout = &out
	err := internal.RunTimeout(cmd, Timeout.Duration)
	if err != nil {
		return &out, fmt.Errorf("error running wg: %s (%s %v)", err, cmdName, cmdArgs)
	}

	return &out, nil
}

// Gather WireGuard stats and add them to the Accumulator
func (s *Wireguard) Gather(acc telegraf.Accumulator) error {

	// TODO filter if necessary

	out, err := s.run(s.Binary, s.Timeout, s.UseSudo)
	if err != nil {
		return fmt.Errorf("error gathering metrics: %s", err)
	}

	fields := make(map[string]interface{})
	fieldsPeers := make(map[string]map[string]interface{})

	// Interface infos will be tags for all peer metrics on this interface
	var ifName, ifPublicKey, ifPort, ifFwmark string

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		stat, value, err := splitStringAfterColon(scanner.Text())
		if err != nil {
			continue
		}

		// is this an interface definition ?
		if strings.HasPrefix(stat, "interface") {
			ifName = value
			// the next 4 lines belong to this interface, so process them here
			for i := 0; i < 4; i++ {
				scanner.Scan()
				stat, value, err := splitStringAfterColon(scanner.Text())
				if err != nil {
					continue
				}

				if strings.HasPrefix(stat, "public key") {
					ifPublicKey = value
				} else if strings.HasPrefix(stat, "private key") {
					continue
				} else if strings.HasPrefix(stat, "listening port") {
					ifPort = value
				} else if strings.HasPrefix(stat, "fwmark") {
					ifFwmark = value
				}
			}
			continue
		}
		if strings.HasPrefix(stat, "peer") {
			// this will be another tag
			peerPublicKey := value
			if fieldsPeers[peerPublicKey] == nil {
				fieldsPeers[peerPublicKey] = make(map[string]interface{})
			}
			// next 4 values belong together
			for i := 0; i < 4; i++ {
				scanner.Scan()
				stat, value, err := splitStringAfterColon(scanner.Text())
				if err != nil {
					continue
				}

				if strings.HasPrefix(stat, "endpoint") {
					fieldsPeers[peerPublicKey][stat] = value
				} else if strings.HasPrefix(stat, "allowed ips") {
					// TODO account for multiple allowed ips and maybe make tags
					fieldsPeers[peerPublicKey][stat] = value
				} else if strings.HasPrefix(stat, "latest handshake") {
					// TODO convert to number
					fieldsPeers[peerPublicKey][stat] = value
				} else if strings.HasPrefix(stat, "transfer") {
					// TODO split into sent and received
					fieldsPeers[peerPublicKey][stat] = value
				}
			}
		}
	}
}

func splitStringAfterColon(input string) (stat, value string, err error) {
	cols := strings.SplitN(input, ":", 2)
	// probably an empty or otherwise unneeded line
	if len(cols) < 2 {
		return stat, value, fmt.Errorf("Not a valid string for splitting: %s", input)
	}
	stat = cols[0]
	value = cols[1]
	return stat, value, nil
}