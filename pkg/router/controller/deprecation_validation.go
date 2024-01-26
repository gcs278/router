package controller

import (
	kapi "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/watch"

	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/router/pkg/router"
	"github.com/openshift/router/pkg/router/routeapihelpers"
)

// DeprecationValidation implements the router.Plugin interface to provide
// deprecated route validation.
type DeprecationValidation struct {
	// plugin is the next plugin in the chain.
	plugin router.Plugin

	// recorder is an interface for indicating route status.
	recorder RouteStatusRecorder
}

// NewDeprecationValidation creates a plugin wrapper that validates routes
// for deprecation and adds a deprecated status if needed. It does not stop
// the plugin chain if the route is deprecated.
// Recorder is an interface for indicating routes status update.
func NewDeprecationValidation(plugin router.Plugin, recorder RouteStatusRecorder) *DeprecationValidation {
	return &DeprecationValidation{
		plugin:   plugin,
		recorder: recorder,
	}
}

// HandleNode processes watch events on the node resource
func (p *DeprecationValidation) HandleNode(eventType watch.EventType, node *kapi.Node) error {
	return p.plugin.HandleNode(eventType, node)
}

// HandleEndpoints processes watch events on the Endpoints resource.
func (p *DeprecationValidation) HandleEndpoints(eventType watch.EventType, endpoints *kapi.Endpoints) error {
	return p.plugin.HandleEndpoints(eventType, endpoints)
}

// HandleRoute processes watch events on the Route resource.
func (p *DeprecationValidation) HandleRoute(eventType watch.EventType, route *routev1.Route) error {
	// Check if route is deprecated.
	routeName := routeNameKey(route)
	if err := routeapihelpers.DeprecatedValidateRoute(route).ToAggregate(); err != nil {
		log.Error(err, "route failed post upgrade validation", "route", routeName)
		p.recorder.RecordRouteDeprecated(route, "DeprecatedValidationFailed", err.Error())
	} else {
		p.recorder.RecordRouteNotDeprecated(route)
	}

	return p.plugin.HandleRoute(eventType, route)
}

// HandleNamespaces limits the scope of valid routes to only those that match
// the provided namespace list.
func (p *DeprecationValidation) HandleNamespaces(namespaces sets.String) error {
	return p.plugin.HandleNamespaces(namespaces)
}

func (p *DeprecationValidation) Commit() error {
	return p.plugin.Commit()
}
