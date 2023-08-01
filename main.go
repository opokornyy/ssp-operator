/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	"github.com/prometheus/client_golang/prometheus/promhttp"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	ocpconfigv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/crypto"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"kubevirt.io/ssp-operator/controllers"
	"kubevirt.io/ssp-operator/internal/common"
	common_templates "kubevirt.io/ssp-operator/internal/operands/common-templates"
	"kubevirt.io/ssp-operator/webhooks"
	// +kubebuilder:scaffold:imports
)

var (
	setupLog = ctrl.Log.WithName("setup")

	// Default certificate directory operator-sdk expects to have
	sdkTLSDir = fmt.Sprintf("%s/k8s-webhook-server/serving-certs", os.TempDir())
)

const (
	// Do not change the leader election ID, otherwise multiple SSP operator instances
	// can be running during upgrade.
	leaderElectionID = "734f7229.kubevirt.io"

	// Certificate directory and file names OLM mounts certificates to
	olmTLSDir = "/apiserver.local.config/certificates"
	olmTLSCrt = "apiserver.crt"
	olmTLSKey = "apiserver.key"

	// Default cert file names operator-sdk expects to have
	sdkTLSCrt = "tls.crt"
	sdkTLSKey = "tls.key"

	webhookPort = 9443
)

func getConfigForClientCallback(cfg *tls.Config) (*tls.Config, error) {
	var err error

	if controllers.TLSProfile == nil {
		cfg.MinVersion = crypto.DefaultTLSVersion()
		cfg.CipherSuites = nil
		return cfg, nil
	}

	if controllers.TLSProfile.Type == ocpconfigv1.TLSProfileCustomType {
		cfg.CipherSuites = common.CipherIDs(controllers.TLSProfile.Custom.Ciphers)
		cfg.MinVersion, err = crypto.TLSVersion(string(controllers.TLSProfile.Custom.MinTLSVersion))
		if err != nil {
			return nil, err
		}
		return cfg, nil
	}

	cipherNames, minTypedTLSVersion := ocpconfigv1.TLSProfiles[controllers.TLSProfile.Type].Ciphers, ocpconfigv1.TLSProfiles[controllers.TLSProfile.Type].MinTLSVersion
	cfg.CipherSuites = common.CipherIDs(cipherNames)
	cfg.MinVersion, err = crypto.TLSVersion(string(minTypedTLSVersion))
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func getPrometheusTLSConfig(ctx context.Context, certWatcher *certwatcher.CertWatcher) *tls.Config {
	return &tls.Config{
		// This callback executes on each client call returning a new config to be used
		// please be aware that the APIServer is using http keepalive so this is going to
		// be executed only after a while for fresh connections and not on existing ones
		GetConfigForClient: func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
			cfg := &tls.Config{}
			cfg.GetCertificate = certWatcher.GetCertificate
			return getConfigForClientCallback(cfg)
		},
	}
}

func runPrometheusServer(metricsAddr string, ctx context.Context) error {
	setupLog.Info("Starting Prometheus metrics endpoint server with TLS")
	metrics.Registry.MustRegister(common_templates.CommonTemplatesRestored)
	metrics.Registry.MustRegister(common.SSPOperatorReconcilingProperly)
	handler := promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{})
	mux := http.NewServeMux()
	mux.Handle("/metrics", handler)

	certPath := path.Join(sdkTLSDir, sdkTLSCrt)
	keyPath := path.Join(sdkTLSDir, sdkTLSKey)

	certWatcher, err := certwatcher.New(certPath, keyPath)
	if err != nil {
		return err
	}

	go func() {
		if err := certWatcher.Start(ctx); err != nil {
			setupLog.Error(err, "certificate watcher error")
		}
	}()

	tlsConfig := getPrometheusTLSConfig(ctx, certWatcher)
	server := http.Server{
		Addr:      metricsAddr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	go func() {
		err := server.ListenAndServeTLS(certPath, keyPath)
		if err != nil {
			setupLog.Error(err, "Failed to start Prometheus metrics endpoint server")
		}
	}()
	return nil
}

func getTLSConfigFunc(ctx context.Context) func(*tls.Config) {
	return func(cfg *tls.Config) {
		// This callback executes on each client call returning a new config to be used
		// please be aware that the APIServer is using http keepalive so this is going to
		// be executed only after a while for fresh connections and not on existing ones
		cfg.GetConfigForClient = func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
			return getConfigForClientCallback(cfg)
		}
	}
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8443", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	err := createCertificateSymlinks()
	if err != nil {
		setupLog.Error(err, "Error creating certificate symlinks")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()

	err = runPrometheusServer(metricsAddr, ctx)
	if err != nil {
		setupLog.Error(err, "unable to start prometheus server")
		os.Exit(1)
	}

	getWebhookTLSConfig := []func(*tls.Config){getTLSConfigFunc(ctx)}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 common.Scheme,
		MetricsBindAddress:     "0",
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       leaderElectionID,
		WebhookServer: &webhook.Server{
			Port:    webhookPort,
			TLSOpts: getWebhookTLSConfig,
		},
	})

	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if os.Getenv("ENABLE_WEBHOOKS") != "false" {
		if err = webhooks.Setup(mgr); err != nil {
			setupLog.Error(err, "unable to create webhook", "webhook", "SSP")
			os.Exit(1)
		}
	}
	if err := mgr.AddReadyzCheck("check", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}
	if err := mgr.AddHealthzCheck("health", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}

	// +kubebuilder:scaffold:builder
	if err = controllers.CreateAndStartReconciler(ctx, mgr); err != nil {
		setupLog.Error(err, "unable to create or start controller", "controller", "SSP")
		os.Exit(1)
	}
}

func createCertificateSymlinks() error {
	olmDir, olmDirErr := os.Stat(olmTLSDir)
	_, sdkDirErr := os.Stat(sdkTLSDir)

	// If certificates are generated by OLM, we should use OLM certificates mount path
	if olmDirErr == nil && olmDir.IsDir() && os.IsNotExist(sdkDirErr) {
		// For some reason, OLM maps the cert/key files to apiserver.crt/apiserver.key
		// instead of tls.crt/tls.key like the SDK expects. Creating symlinks to allow
		// the operator to find and use them.
		setupLog.Info("OLM cert directory found, copying cert files")

		err := os.MkdirAll(sdkTLSDir, 0755)
		if err != nil {
			return fmt.Errorf("failed to create %s: %w", sdkTLSCrt, err)
		}

		err = os.Symlink(path.Join(olmTLSDir, olmTLSCrt), path.Join(sdkTLSDir, sdkTLSCrt))
		if err != nil {
			return err
		}

		err = os.Symlink(path.Join(olmTLSDir, olmTLSKey), path.Join(sdkTLSDir, sdkTLSKey))
		if err != nil {
			return err
		}
	} else {
		setupLog.Info("OLM cert directory not found, using default cert directory")
	}

	return nil
}
