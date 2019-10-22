// Copyright 2018 Comcast Cable Communications Management, LLC
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto/tls"
	"net/http"
	"os"
	"os/signal"
	"strconv"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes/scheme"
	// khcheckcrd "github.com/Comcast/kuberhealthy/pkg/khcheckcrd"
)

var (

	// Respect HTTP / HTTPS option requests.
	httpsEnabledEnv = os.Getenv("ENABLE_HTTPS")
	httpsEnabled    = true

	addr = ":443"

	// TLS certificate path.
	tlsCertEnv = os.Getenv("TLS_CERT")
	tlsCert    string

	// TLS key path.
	tlsKeyEnv = os.Getenv("TLS_KEY")
	tlsKey    string

	// Schema deserializer.
	deserializer runtime.Decoder

	// KHCheckCRD resource.
	khcheckCRDResource metav1.GroupVersionResource

	// Signal channel for interrupts.
	signalChan chan os.Signal

	debugEnv = os.Getenv("DEBUG")
	debug    bool
)

const (

	// HTTP header values.
	httpHeaderContentType = "Content-type"

	// HTTP content type.
	contentTypeJSON = "application/json"

	// Mutating webhook patch type.
	jsonPatchType = "JSONPatch"

	// KHCheckCRD values.
	resource = "khchecks"
	group    = "comcast.github.io"
	version  = "v1"
)

func init() {

	// Load TLS configurations
	if len(tlsCertEnv) != 0 {
		tlsCert = tlsCertEnv
	}

	if len(tlsKeyEnv) != 0 {
		tlsKey = tlsKeyEnv
	}

	// Use HTTPS if requested.
	if len(httpsEnabledEnv) != 0 {
		useHTTPS, err := strconv.ParseBool(httpsEnabledEnv)
		if err != nil {
			log.Fatalln("Unable to parse ENABLE_HTTPS:", err)
		}

		httpsEnabled = useHTTPS
	}

	// Parse TLS cert and key if HTTPS is enabled.
	if httpsEnabled {
		if len(tlsCert) == 0 {
			log.Fatalln("HTTPS enabled, but no TLS certificate provided.")
		}
		if len(tlsKey) == 0 {
			log.Fatalln("HTTPS enabled, but no TLS key provided.")
		}
	} else {
		addr = ":80"
	}

	// Set up a runtime decoder.
	deserializer = serializer.WithoutConversionCodecFactory{CodecFactory: scheme.Codecs}.UniversalDeserializer()

	// Set up a KHCheckCRD.
	khcheckCRDResource = metav1.GroupVersionResource{
		Group:    group,
		Version:  version,
		Resource: resource,
	}

	// Make the signal channel.
	signalChan = make(chan os.Signal, 2)

	// Enable debug logging if requested.
	if len(debugEnv) != 0 {
		var err error
		debug, err = strconv.ParseBool(debugEnv)
		if err != nil {
			log.Fatalln("Failed to parse rolling update target image variable:", err)
		}
	}

	// Turn on debug logging.
	if debug {
		log.Infoln("Debug logging enabled.")
		log.SetLevel(log.DebugLevel)
	}
	log.Debugln(os.Args)
}

func main() {

	// Create a TLS certificate configuration.
	cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
	if err != nil {
		log.Fatalln("Failed to load certification configuration:", err)
	}

	// Configure the multiplexer.
	mux := http.NewServeMux()
	mux.Handle("/validate", validateHandlerWrapper())

	// Create server configurations and handlers.
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	go listenForInterrupts()

	// Start the server.
	if httpsEnabled {
		err = server.ListenAndServeTLS(tlsCert, tlsKey)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil {
		log.Fatalln("Failed to start server:", err)
	}
}

// listenForInterrupts watches the signal and done channels for termination.
func listenForInterrupts() {

	// Relay incoming OS interrupt signals to the signalChan.
	signal.Notify(signalChan, os.Interrupt, os.Kill)
	<-signalChan // This is a blocking operation -- the routine will stop here until there is something sent down the channel.
	log.Infoln("Received an interrupt signal from the signal channel.")
	log.Infoln("Shutting down.")

	os.Exit(0)
}
