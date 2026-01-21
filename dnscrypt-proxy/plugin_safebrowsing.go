package main

import ( 
	"codeberg.org/miekg/dns"
 	"github.com/google/safebrowsing"
	"os"
	"context"
	"github.com/jedisct1/dlog"
)

var safeBrowser, safeBrowserInitError = safebrowsing.NewSafeBrowser(getSafeBrowsingConfig())

type PluginSafeBrowsing struct {
	safeBrowsingConf safebrowsing.Config
	safeBrowser, err safebrowsing.SafeBrowser
}

func (plugin *PluginSafeBrowsing) Name() string {
	return "safe_browsing"
}

func (plugin *PluginSafeBrowsing) Description() string {
	return "Check DNS queries against Google Safe Browsing"
}

func (plugin *PluginSafeBrowsing) Init(proxy *Proxy) error {
	if proxy.safeBrowsing == "disabled" {
		dlog.Info("Safebrowsing has been disabled by config file.")
		safeBrowser.Close()
	}

	return nil

}

func (plugin *PluginSafeBrowsing) Drop() error {
	return nil
}

func (plugin *PluginSafeBrowsing) Reload() error {
	return nil
}

func (plugin *PluginSafeBrowsing) Eval(pluginsState *PluginsState, msg *dns.Msg) error {

	config := newConfig()

	if config.SafeBrowsing == "disabled" {
		dlog.Info("skipping safebrowsing plugin since safebrowsing is disabled in scamjam-dns-server settings")
		return nil
	}

	if safeBrowserInitError != nil {
		dlog.Error("Detected Safe Browsing client init error: " + safeBrowserInitError.Error() + " Bypassing Safe Browsing protection due to error")
		return nil
	}

	if pluginsState.qName == "internetbeacon.msedge.net" {
		dlog.Info("skipping domain internetbeacon.msedge.net since it's known safe and used by scamjam-dns-watcher to test for connectivity")
		return nil
	}

	url := []string{pluginsState.qName}

	sbResponse, err := safeBrowser.LookupURLsContext(context.Background(), url)
	if err != nil {
		dlog.Warn("Error occured during safe browsing lookup:" + err.Error() + "trying to continue but response may be stale or incomplete.")
	}

	if len(sbResponse[0]) > 0 {
		dlog.Warn("Hostname has been found on a safe browsing threat list!" + pluginsState.qName)
		dlog.Warn("Querry will be blocked.")
		pluginsState.action = PluginsActionReject  
        pluginsState.returnCode = PluginsReturnCodeReject
		return nil
	}

	dlog.Info(pluginsState.qName + " is not on any safebrowsing blocklists.")

	return nil
}

func getSafeBrowsingDatabasePath() (string) {
	safeBrowsingWorkingDir, err := os.Getwd()
	if err != nil { 
		dlog.Error("Could not get working directory! Safe browsing database will run from non-persistant memory" + err.Error())
		return ""
	} 

	safeBrowsingDatabasePath := safeBrowsingWorkingDir + "\\sb-database"

	return safeBrowsingDatabasePath


}

func getSafeBrowsingConfig() (safebrowsing.Config) {
	config := newConfig()
	safeBrowsingConfig := safebrowsing.Config {
		APIKey:   "AIzaSyDMH4I7u-uSNLHvUO8vUbDoX2CToN5NhVk",
		DBPath:  getSafeBrowsingDatabasePath(),
		ID:   "scamjam-dns",
		Version:   "1.0",
		Logger:   os.Stdout,
	}
	switch{
	case config.SafeBrowsing == "enabled":
		safeBrowsingConfig.Enabled = true
		return safeBrowsingConfig
	case config.SafeBrowsing == "disabled":
		safeBrowsingConfig.Enabled = false
		return safeBrowsingConfig
	default: 
		dlog.Error("config.SafeBrowsing in scamjam-dns-server settings is invalid! Running with safebrowsing disabled.")
		safeBrowsingConfig.Enabled = false
		return safeBrowsingConfig
	}
}