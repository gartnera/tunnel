package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"

	"github.com/jamiealquiza/envy"
	"github.com/myesui/uuid"
	"github.com/spf13/cobra"
	"gitlab.com/gartnera/tunnel/client"
)

var defaultServer string

const (
	tokenArgName                = "token"
	serverArgName               = "server"
	hostnameArgName             = "hostname"
	useTlsArgName               = "use-tls"
	tlsSkipVerifyArgName        = "tls-skip-verify"
	httpTargetHostHeaderArgName = "http-target-host-header"
)

func init() {
	flags := rootCmd.Flags()
	flags.String(tokenArgName, uuid.NewV4().String(), "Secret token")
	flags.StringArray(serverArgName, []string{defaultServer}, "Tunnel server(s)")
	hostnameHelp := fmt.Sprintf("Hostname to request (test.%s)", defaultServer)
	flags.String(hostnameArgName, "", hostnameHelp)
	flags.Bool(useTlsArgName, false, "use TLS when connecting to the local server")
	flags.Bool(tlsSkipVerifyArgName, false, "skip tls verification of the local server")
	flags.Bool(httpTargetHostHeaderArgName, false, "rewrite the host header to match the target host")
}

var rootCmd = &cobra.Command{
	Use:     "tunnel <[http://]hostname:port>",
	Short:   "Start a tunnel to a local server",
	Example: "tunnel localhost:8888",
	Args:    cobra.ExactArgs(1),
	// use envy to parse TUNNEL_ vars into environment
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		envy.ParseCobra(cmd, envy.CobraConfig{
			Prefix: "TUNNEL",
		})
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		log.SetFlags(log.Lshortfile)

		target := args[0]

		flags := cmd.Flags()
		token, err := flags.GetString(tokenArgName)
		if err != nil {
			return err
		}
		servers, err := flags.GetStringArray(serverArgName)
		if err != nil {
			return err
		}
		hostname, err := flags.GetString(hostnameArgName)
		if err != nil {
			return err
		}
		useTLS, err := flags.GetBool(useTlsArgName)
		if err != nil {
			return err
		}
		tlsSkipVerify, err := flags.GetBool(tlsSkipVerifyArgName)
		if err != nil {
			return err
		}
		httpTargetHostHeader, err := flags.GetBool(httpTargetHostHeaderArgName)
		if err != nil {
			return err
		}

		tunnels := []*client.Tunnel{}
		for _, server := range servers {
			// we now use the control subdomain rather than the basename of the server
			controlName := fmt.Sprintf("control.%s", server)
			if !strings.Contains(server, ":") {
				controlName += ":443"
			}
			hostnameFqdn := hostname
			if !strings.Contains(hostnameFqdn, ".") {
				hostnameFqdn = strings.Join([]string{hostname, server}, ".")
			}

			tunnel := client.NewTunnel(controlName, hostnameFqdn, token, useTLS, tlsSkipVerify, httpTargetHostHeader, target)
			tunnel.Start()
			tunnels = append(tunnels, tunnel)
		}

		signalChannel := make(chan os.Signal, 1)
		signal.Notify(signalChannel, os.Interrupt)
		<-signalChannel
		for _, tunnel := range tunnels {
			tunnel.Shutdown()
		}

		return nil
	},
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
