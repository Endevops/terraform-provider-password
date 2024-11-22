// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccArgon2Resource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccArgon2ResourceConfig("example-password", "example-salt"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("password_argon2.test", "password", "example-password"),
					resource.TestCheckResourceAttr("password_argon2.test", "salt", "example-salt"),
					resource.TestCheckResourceAttr("password_argon2.test", "id", "argon2-id"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "password_example.test",
				ImportState:       true,
				ImportStateVerify: true,
				// This is not normally necessary, but is here because this
				// example code does not have an actual upstream service.
				// Once the Read method is able to refresh information from
				// the upstream service, this can be removed.
				ImportStateVerifyIgnore: []string{"configurable_attribute", "defaulted"},
			},
			// Update and Read testing
			{
				Config: testAccArgon2ResourceConfig("new-password", "new-salt"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("password_argon2.test", "password", "new-password"),
					resource.TestCheckResourceAttr("password_argon2.test", "salt", "new-salt"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccArgon2ResourceConfig(password string, salt string) string {
	return fmt.Sprintf(`
resource "password_argon2" "test" {
  password = %[1]q
  salt = %[2]q
}
`, password, salt)
}
