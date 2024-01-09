package controller

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus"

	kapi "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"

	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/router/pkg/router"
	"github.com/openshift/router/pkg/router/routeapihelpers"
)

// ExtendedValidator implements the router.Plugin interface to provide
// extended config validation for template based, backend-agnostic routers.
type ExtendedValidator struct {
	// plugin is the next plugin in the chain.
	plugin router.Plugin

	// recorder is an interface for indicating route rejections.
	recorder RejectionRecorder

	metricPostUpgradeInvalidRoute prometheus.Gauge
}

// NewExtendedValidator creates a plugin wrapper that ensures only routes that
// pass extended validation are relayed to the next plugin in the chain.
// Recorder is an interface for indicating why a route was rejected.
func NewExtendedValidator(plugin router.Plugin, recorder RejectionRecorder) *ExtendedValidator {
	metricPostUpgradeInvalidRoute := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "template_router",
		Name:      "post_invalid_route",
		Help:      "Metric to track number of routes that would be invalid in the next upgrade.",
	})
	prometheus.MustRegister(metricPostUpgradeInvalidRoute)

	return &ExtendedValidator{
		plugin:                        plugin,
		recorder:                      recorder,
		metricPostUpgradeInvalidRoute: metricPostUpgradeInvalidRoute,
	}
}

// HandleNode processes watch events on the node resource
func (p *ExtendedValidator) HandleNode(eventType watch.EventType, node *kapi.Node) error {
	return p.plugin.HandleNode(eventType, node)
}

// HandleEndpoints processes watch events on the Endpoints resource.
func (p *ExtendedValidator) HandleEndpoints(eventType watch.EventType, endpoints *kapi.Endpoints) error {
	return p.plugin.HandleEndpoints(eventType, endpoints)
}

// HandleRoute processes watch events on the Route resource.
func (p *ExtendedValidator) HandleRoute(eventType watch.EventType, route *routev1.Route) error {
	// Check if previously seen route and its Spec is unchanged.
	routeName := routeNameKey(route)
	if err := routeapihelpers.ExtendedValidateRoute(route).ToAggregate(); err != nil {
		log.Error(err, "skipping route due to invalid configuration", "route", routeName)

		p.recorder.RecordRouteRejection(route, "ExtendedValidationFailed", err.Error())
		p.plugin.HandleRoute(watch.Deleted, route)
		return fmt.Errorf("invalid route configuration")
	} else if err := routeapihelpers.PostUpgradeRouteValidation(route).ToAggregate(); err != nil {
		log.Error(err, "route failed post upgrade validation", "route", routeName)
		p.metricPostUpgradeInvalidRoute.Add(1)
	}

	return p.plugin.HandleRoute(eventType, route)
}

// HandleNamespaces limits the scope of valid routes to only those that match
// the provided namespace list.
func (p *ExtendedValidator) HandleNamespaces(namespaces sets.String) error {
	return p.plugin.HandleNamespaces(namespaces)
}

func (p *ExtendedValidator) Commit() error {
	return p.plugin.Commit()
}
