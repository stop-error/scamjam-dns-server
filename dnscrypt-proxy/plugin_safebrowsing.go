package main

import ( 
	"codeberg.org/miekg/dns"
 	"github.com/google/safebrowsing"
	"os"
	"context"
	"github.com/jedisct1/dlog"
)

var safeBrowsingDisabled int = 0

var safeBrowsingWorkingDir, err = os.Getwd()

var safeBrowsingConf = safebrowsing.Config {
		APIKey:   "YOUR_API_KEY_HERE",
		DBPath:   safeBrowsingWorkingDir + "\\sb-database",
		ID:   "scamjam-dns",
		Version:   "1.0",
		Logger:   os.Stdout,
	}

var safeBrowser, safeBrowserInitError = safebrowsing.NewSafeBrowser(safeBrowsingConf)

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
		dlog.Info("Safebrowsing has been disabled by config file")
		safeBrowsingDisabled = 1
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

	if pluginsState.qName == "internetbeacon.msedge.net" {
		dlog.Info("skipping domain internetbeacon.msedge.net since it's known safe and used by scamjam-dns-watcher to test for connectivity")
		return nil
	}

	if safeBrowserInitError != nil {
		dlog.Error("Detected Safe Browsing client init error: " + safeBrowserInitError.Error() + " Bypassing Safe Browsing protection due to error")
		return nil
	}

	if safeBrowsingDisabled == 1 {
		dlog.Info("Skipping safe browsing since it's been disabled")
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
	} else {
		dlog.Info(pluginsState.qName + " is not on any safebrowsing blocklists.")
	}

	return nil
}
