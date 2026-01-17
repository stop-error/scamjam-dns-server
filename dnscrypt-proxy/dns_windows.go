// MIT License

// Copyright (c) 2019 NextDNS Inc

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// https://github.com/nextdns/nextdns/

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"github.com/jedisct1/dlog"
)

func DNS() []string {
	return nil
}

func SetDNS(dns string) error {
	dlog.Info("Setting host DNS to" + dns)
	ifaces, err := getInterfaces()
	if err != nil {
		return err
	}
	for _, idx := range ifaces {
		if e := winSetDNS(idx, dns); err == nil {
			err = e
		}
	}
	return err
}

func ResetDNS() error {
	dlog.Info("Resetting DNS to DHCP")
	ifaces, err := getInterfaces()
	if err != nil {
		return err
	}
	for _, idx := range ifaces {
		if e := winResetDNS(idx); err == nil {
			err = e
		}
	}
	return nil
}

func winSetDNS(idx, dns string) error {
	err := netsh("interface", "ipv4", "set", "dnsserver", idx, "static", dns, "primary")
	netsh("interface", "ipv6", "set", "dnsserver", idx, "static", "::1", "primary") // TODO: properly handle v6
	if err != nil {
		err = fmt.Errorf("set %s %s: %v", idx, dns, err)
	}
	return err
}

func winResetDNS(idx string) error {
	err := netsh("interface", "ipv4", "set", "dnsserver", idx, "dhcp")
	netsh("interface", "ipv6", "set", "dnsserver", idx, "dhcp")
	if err != nil {
		err = fmt.Errorf("reset dns %s: %v", idx, err)
	}
	return err
}

func netsh(args ...string) error {
	b, err := exec.Command("netsh", args...).Output()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(b))
	}
	return nil
}

func getInterfaces() (ifaces []string, err error) {
	b, err := exec.Command("netsh", "interface", "ipv4", "show", "interfaces").Output()
	if err != nil {
		return nil, err
	}
	s := bufio.NewScanner(bytes.NewReader(b))
	for s.Scan() {
		line := s.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if _, err := strconv.ParseUint(fields[0], 10, 32); err != nil {
			continue
		}
		ifaces = append(ifaces, fields[0])
	}
	return ifaces, nil
}
