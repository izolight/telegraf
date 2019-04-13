package wireguard

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/filter"
	"github.com/influxdata/telegraf/internal"
	"github.com/influxdata/telegraf/plugins/inputs"
)

type runner func(cmdName string, timeout internal.Duration, useSudo bool) (*bytes.Buffer, error)

type WireGuard struct {
	Binary  string
	Timeout internal.Duration
	UseSudo bool

	filter filter.Filter
	run    runner
}

var defaultBinary = "/usr/bin/wg"
var defaultTimeout = internal.Duration{Duration: time.Second}

var sampleConfig = `
  ## If running as a restricted user you can prepend sudo for additional access:
  # use_sudo = false

  ## The default location of the unbound-control binary can be overridden with:
  # binary = "/usr/bin/wg"

  ## The default timeout of 1s can be overridden with:
  # timeout = "1s"
`

// Description displays what this plugin is about
func (w *WireGuard) Description() string {
	return "A plugin to collect stats from the WireGuard VPN"
}

// SampleConfig displays configuration instructions
func (w *WireGuard) SampleConfig() string {
	return sampleConfig
}

func wireGuardRunner(cmdName string, timeout internal.Duration, useSudo bool) (*bytes.Buffer, error) {
	cmdArgs := []string{"show", "all", "dump"}
	cmd := exec.Command(cmdName, cmdArgs...)
	if useSudo {
		cmdArgs = append([]string{cmdName}, cmdArgs...)
		cmd = exec.Command("sudo", cmdArgs...)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	err := internal.RunTimeout(cmd, timeout.Duration)
	if err != nil {
		return &out, fmt.Errorf("error running wg: %s (%s %v)", err, cmdName, cmdArgs)
	}
	return &out, nil
}

func (w *WireGuard) Gather(acc telegraf.Accumulator) error {
	out, err := w.run(w.Binary, w.Timeout, w.UseSudo)
	if err != nil {
		return fmt.Errorf("error gathering metrics: %s", err)
	}

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		cols := strings.Split(scanner.Text(), "\t")
		/*
		   If dump is specified, then several lines  are  printed;  the  first contains  in order separated by tab:
		   private-key, public-key, listen-port, fwmark. Subsequent lines are printed for each peer and contain in order
		   separated by tab: public-key, preshared-key, endpoint, allowed-ips, latest-handshake, transfer-rx, transfer-tx,
		   persistent-keepalive.
		*/
		fields := make(map[string]interface{})
		tags := make(map[string]string)
		tags["interface"] = cols[0]
		// first line
		if len(cols) == 5 {
			//privateKey := cols[1] // probably shouldn't gather that
			tags["publicKey"] = cols[2]
			tags["listenPort"] = cols[3]
			//fwmark := cols[4]
			acc.AddFields("wireguard", fields, tags)
			continue
		} else if len(cols) < 5 || len(cols) > 9 {
			continue
		}
		tags["publicKey"] = cols[1]
		//presharedKey := cols[2]
		//endPointString := cols[3]
		tags["endPoint"] = cols[3]
		/*
		   endPoint := &net.UDPAddr{}
		   if endPointString != "(none)" {
		       endPoint, err := net.ResolveUDPAddr("udp", endPointString)
		       if err != nil {
		           acc.AddError(fmt.Errorf("Expected a udp address for endpoint = %v: %s", endPoint, err))
		           continue
		       }
		   }
		*/
		tags["allowedIPs"] = cols[4]
		/*
		   allowedIPStrings := strings.Split(cols[4], ",")
		   allowedIPs := []*net.UDPAddr{}
		   for _, allowedIPString := range allowedIPStrings {
		       allowedIP, err := net.ResolveUDPAddr("udp", allowedIPString)
		       if err != nil {
		           acc.AddError(fmt.Errorf("Expected a udp address for allowedIP = %v: %s", allowedIP, err))
		           continue
		       }
		       allowedIPs = append(allowedIPs, allowedIP)
		   }
		*/
		latestHandshake, err := strconv.ParseUint(cols[5], 10, 64)
		if err != nil {
			acc.AddError(fmt.Errorf("Expected a numerical value for port = %v", latestHandshake))
			continue
		}
		fields["latestHandshake"] = latestHandshake
		transferRx, err := strconv.ParseUint(cols[6], 10, 64)
		if err != nil {
			acc.AddError(fmt.Errorf("Expected a numerical value for port = %v", transferRx))
			continue
		}
		fields["transferRx"] = transferRx
		transferTx, err := strconv.ParseUint(cols[7], 10, 64)
		if err != nil {
			acc.AddError(fmt.Errorf("Expected a numerical value for port = %v", transferTx))
			continue
		}
		fields["transferTx"] = transferTx
		tags["persistentKeepalive"] = cols[8]

		acc.AddFields("wireguard", fields, tags)
	}
	return nil
}

func init() {
	inputs.Add("wireguard", func() telegraf.Input {
		return &WireGuard{
			run:     wireGuardRunner,
			Binary:  defaultBinary,
			Timeout: defaultTimeout,
			UseSudo: false,
		}
	})
}
