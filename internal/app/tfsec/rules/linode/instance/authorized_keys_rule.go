package instance

import (
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		Provider:  provider.AzureProvider,
		Service:   "instance",
		ShortCode: "authorized-keys",
		Documentation: rule.RuleDocumentation{
			Summary:     "Linode Instance is missing the Authorized Keys block",
			Explanation: `<TODO>`,
			Impact:      "It is best practice to use keys",
			Resolution:  "Enable and list authorized keys",
			BadExample: []string{`
			resource "linode_instance" "bad_example" {
				label = "simple_instance"
				image = "linode/ubuntu18.04"
				region = "us-central"
				type = "g6-standard-1"
			}		
`},
			GoodExample: []string{`
			resource "linode_instance" "good_example" {
				label = "simple_instance"
				image = "linode/ubuntu18.04"
				region = "us-central"
				type = "g6-standard-1"
				authorized_keys = ["ssh-rsa AAAA...Gw== user@example.local"]
			}	
`},
			Links: []string{
				"https://registry.terraform.io/providers/linode/linode/latest/docs/resources/instance#authorized_keys",
			},
		},
		RequiredTypes: []string{
			"resource",
		},
		RequiredLabels: []string{
			"linode_instance",
		},
		DefaultSeverity: severity.Low,
		CheckFunc: func(set result.Set, resourceBlock block.Block, module block.Module) {
			if resourceBlock.MissingChild("authorized_keys") {
				set.AddResult().
					WithDescription("Resource '%s' should have a content type set.", resourceBlock.FullName())
			}
		},
	})
}
