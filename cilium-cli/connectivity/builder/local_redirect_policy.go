// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	_ "embed"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/pkg/versioncheck"
)

var (
	//go:embed manifests/local-redirect-policy.yaml
	localRedirectPolicyYAML string
	//go:embed manifests/client-egress-to-cidr-lrp-frontend-deny.yaml
	localRedirectPolicyFrontendDenyYAML string
)

type localRedirectPolicy struct{}

func (t localRedirectPolicy) build(ct *check.ConnectivityTest, _ map[string]string) {
	lrpFrontendIPV4 := "169.254.169.254"
	lrpFrontendIPV6 := "fd00::169:254:169:254"
	lrpFrontendIPSkipRedirectV4 := "169.254.169.255"
	lrpFrontendIPSkipRedirectV6 := "fd00::169:254:169:255"

	newTest("local-redirect-policy", ct).
		WithCondition(func() bool {
			if versioncheck.MustCompile(">=1.16.0")(ct.CiliumVersion) {
				if isSocketLBFull(ct) || versioncheck.MustCompile(">=1.17.0")(ct.CiliumVersion) {
					return true
				}
			}
			return false
		}).
		WithCiliumLocalRedirectPolicy(check.CiliumLocalRedirectPolicyParams{
			Policy:                  localRedirectPolicyYAML,
			Name:                    "lrp-address-matcher-v4",
			FrontendIP:              lrpFrontendIPV4,
			SkipRedirectFromBackend: false,
		}).
		WithCiliumLocalRedirectPolicy(check.CiliumLocalRedirectPolicyParams{
			Policy:                  localRedirectPolicyYAML,
			Name:                    "lrp-address-matcher-v6",
			FrontendIP:              lrpFrontendIPV6,
			SkipRedirectFromBackend: false,
		}).
		WithCiliumPolicy(localRedirectPolicyFrontendDenyYAML).
		WithCiliumLocalRedirectPolicy(check.CiliumLocalRedirectPolicyParams{
			Policy:                  localRedirectPolicyYAML,
			Name:                    "lrp-address-matcher-skip-redirect-from-backend-v4",
			FrontendIP:              lrpFrontendIPSkipRedirectV4,
			SkipRedirectFromBackend: true,
		}).
		WithCiliumLocalRedirectPolicy(check.CiliumLocalRedirectPolicyParams{
			Policy:                  localRedirectPolicyYAML,
			Name:                    "lrp-address-matcher-skip-redirect-from-backend-v6",
			FrontendIP:              lrpFrontendIPSkipRedirectV6,
			SkipRedirectFromBackend: true,
		}).
		WithFeatureRequirements(features.RequireEnabled(features.LocalRedirectPolicy)).
		WithScenarios(
			tests.LRP(false),
			tests.LRP(true),
		).
		WithExpectations(func(a *check.Action) (egress, ingress check.Result) {
			if a.Scenario().Name() == "lrp-skip-redirect-from-backend" {
				if a.Source().HasLabel("lrp", "backend") {
					if a.Destination().Address(features.IPFamilyV4) == lrpFrontendIPSkipRedirectV4 {
						return check.ResultPolicyDenyEgressDrop, check.ResultNone
					}
					if a.Destination().Address(features.IPFamilyV6) == lrpFrontendIPSkipRedirectV6 {
						return check.ResultPolicyDenyEgressDrop, check.ResultNone
					}
				}
				return check.ResultOK, check.ResultNone
			}
			return check.ResultOK, check.ResultNone
		})
}

func isSocketLBFull(ct *check.ConnectivityTest) bool {
	socketLBEnabled, _ := ct.Features.MatchRequirements(features.RequireEnabled(features.KPRSocketLB))
	if socketLBEnabled {
		socketLBHostnsOnly, _ := ct.Features.MatchRequirements(features.RequireEnabled(features.KPRSocketLBHostnsOnly))
		return !socketLBHostnsOnly
	}
	return false
}
