package main

import ( 
	"codeberg.org/miekg/dns"
 	"github.com/google/safebrowsing"
	"os"
	"fmt"
	"context"
)

var safeBrowsingDisabled int = 0

var safeBrowsingWorkingDir, err = os.Getwd()

var safeBrowsingConf = safebrowsing.Config {
		APIKey:   "AIzaSyCSKxhmBrXXtGLzVNrKfzTbSiTEBmu2Ia8",
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
		fmt.Fprintln(os.Stdout, "Safebrowsing has been disabled by config file")
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

	if safeBrowserInitError != nil {
		fmt.Fprintln(os.Stderr, "Detected Safe Browsing client init error", safeBrowserInitError,)
		fmt.Fprintln(os.Stderr, "Bypassing Safe Browsing protection.")
		return nil
	}

	if safeBrowsingDisabled == 1 {
		fmt.Fprintln(os.Stdout, "Skipping safe browsing since it's been disabled")
		return nil
	}


	url := []string{pluginsState.qName}

	sbResponse, err := safeBrowser.LookupURLsContext(context.Background(), url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error occured during safe browsing lookup:", err, "trying to continue but response may be stale or incomplete.")
	}

	if len(sbResponse[0]) > 0 {
		fmt.Fprintln(os.Stdout, "Hostname has been found on a safe browsing threat list!", sbResponse[0])
		fmt.Fprintln(os.Stdout, "Querry will be blocked.")
		pluginsState.action = PluginsActionReject  
        pluginsState.returnCode = PluginsReturnCodeReject
		return nil
	} else {
		fmt.Fprintln(os.Stdout, url, "is not on any safebrowsing blocklists.")
	}

	return nil
}
