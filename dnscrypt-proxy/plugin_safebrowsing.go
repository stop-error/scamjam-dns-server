package main

import "codeberg.org/miekg/dns"

type PluginSafeBrowsing struct {
}

func (plugin *PluginSafeBrowsing) Name() string {
	return "safe_browsing"
}

func (plugin *PluginSafeBrowsing) Description() string {
	return "Check DNS queries against Google Safe Browsing"
}

func (plugin *PluginSafeBrowsing) Init(proxy *Proxy) error {

	return nil
}

func (plugin *PluginSafeBrowsing) Drop() error {
	return nil
}

func (plugin *PluginSafeBrowsing) Reload() error {
	return nil
}

func (plugin *PluginSafeBrowsing) Eval(pluginsState *PluginsState, msg *dns.Msg) error {

	return nil
}
