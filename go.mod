module github.com/lmicke/terraform-provider-vcd/v3

go 1.13

require (
	github.com/aws/aws-sdk-go v1.30.12 // indirect
	github.com/hashicorp/go-version v1.2.1
	github.com/hashicorp/terraform-plugin-sdk/v2 v2.2.0
	github.com/lmicke/go-vcloud-director/v2 v2.11.31
)

//replace github.com/lmicke/go-vcloud-director/v2 => ../go-vcloud-director/
