package main

import (
	"crypto/md5"
	"fmt"
	routev1 "github.com/openshift/api/route/v1"
	templaterouter "github.com/openshift/router/pkg/router/template"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"os"
)

func main() {
	routerTemplate := templaterouter.NewFakeTemplateRouter()

	// TODO: Parse arguments to create profiles and dynamically generate these objects
	routerTemplate.AddRoute(&routev1.Route{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test",
			Name:      "test",
		},
		Spec: routev1.RouteSpec{
			Port: &routev1.RoutePort{
				TargetPort: intstr.FromString("port"),
			},
			To: routev1.RouteTargetReference{
				Name: "test",
			},
		},
	})

	endpoint := templaterouter.Endpoint{
		ID:     "test",
		IP:     "ip",
		Port:   "port",
		IdHash: fmt.Sprintf("%x", md5.Sum([]byte("ep1ipport"))),
	}
	routerTemplate.AddEndpoints("test/test", []templaterouter.Endpoint{endpoint})

	// TODO: See if I can reuse code for this function see plugin.go:NewTemplatePlugin
	//       Create a helper function that can just be called from NewFakeTemplateRouter()
	routerTemplate.FakeTemplates(os.Getenv("TEMPLATE_FILE"), "grant")
	
	routerTemplate.FakeWriteConfig()
}
