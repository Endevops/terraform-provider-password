// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"runtime"

	"github.com/go-crypt/crypt/algorithm"
	"github.com/go-crypt/crypt/algorithm/argon2"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int32default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                = &Argon2Resource{}
	_ resource.ResourceWithImportState = &Argon2Resource{}
)

func NewArgon2Resource() resource.Resource {
	return &Argon2Resource{}
}

// Argon2Resource defines the resource implementation.
type Argon2Resource struct{}

// Argon2ResourceModel describes the resource data model.
type Argon2ResourceModel struct {
	Password   types.String `tfsdk:"password"`
	KeyLen     types.Int32  `tfsdk:"key_len"`
	Thread     types.Int32  `tfsdk:"thread"`
	Memory     types.Int32  `tfsdk:"memory"`
	Iterations types.Int32  `tfsdk:"iterations"`
	Hash       types.String `tfsdk:"hash"`
	Id         types.String `tfsdk:"id"`
}

func (r *Argon2Resource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_argon2"
}

func (r *Argon2Resource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: "Argon2 is a password-hashing function that summarizes the state of the art in the design of memory-hard functions and can be used to hash passwords for credential storage.",
		Attributes: map[string]schema.Attribute{
			"password": schema.StringAttribute{
				MarkdownDescription: "The password to hash",
				Required:            true,
				Computed:            false,
				Sensitive:           true,
			},
			"key_len": schema.Int32Attribute{
				MarkdownDescription: "The length of the key to generate",
				Default:             int32default.StaticInt32(argon2.KeyLengthDefault),
				Optional:            true,
				Computed:            true,
			},
			"thread": schema.Int32Attribute{
				MarkdownDescription: "The number of threads to use",
				Default:             int32default.StaticInt32(int32(runtime.NumCPU())),
				Optional:            true,
				Computed:            true,
			},
			"memory": schema.Int32Attribute{
				MarkdownDescription: "The amount of memory to use for hashing (in KiB)",
				Default:             int32default.StaticInt32(argon2.MemoryDefault),
				Optional:            true,
				Computed:            true,
			},
			"iterations": schema.Int32Attribute{
				MarkdownDescription: "Controls the number of iterations",
				Default:             int32default.StaticInt32(argon2.IterationsDefault),
				Computed:            true,
				Optional:            true,
			},
			"hash": schema.StringAttribute{
				MarkdownDescription: "The generated hash",
				Computed:            true,
				Sensitive:           true,
			},
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Argon2 identifier",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *Argon2Resource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}
}

func (r *Argon2Resource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data Argon2ResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// For the purposes of this Argon2 code, hardcoding a response value to
	// save into the Terraform state.
	data.Id = types.StringValue("argon2-id")

	digest := generatePassword(resp.Diagnostics, data)
	if digest == nil {
		return
	}
	data.Hash = types.StringValue(digest.String())

	// Write logs using the tflog package
	// Documentation: https://terraform.io/plugin/log
	tflog.Trace(ctx, "created a resource")

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func generatePassword(diag diag.Diagnostics, data Argon2ResourceModel) algorithm.Digest {
	var (
		hasher *argon2.Hasher
		err    error
		digest algorithm.Digest
	)

	hasher = argon2.ProfileRFC9106Recommended.Hasher()
	if err = hasher.WithOptions(
		argon2.WithIterations(int(data.Iterations.ValueInt32())),
		argon2.WithKeyLength(int(data.KeyLen.ValueInt32())),
		argon2.WithMemoryInKiB(uint32(data.Memory.ValueInt32())),
		argon2.WithVariant(argon2.VariantID),
		argon2.WithParallelism(int(data.Thread.ValueInt32())),
	); err != nil {
		diag.AddError("Argon 2 initialization error", fmt.Sprintf("Unable to generate hash, got error %s", err))
	}

	if digest, err = hasher.Hash(data.Password.ValueString()); err != nil {
		diag.AddError("Argon 2 error", fmt.Sprintf("Unable to hash Argon2, got error: %s", err))
		return nil
	}
	return digest
}

func (r *Argon2Resource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data Argon2ResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// If applicable, this is a great opportunity to initialize any necessary
	// provider client data and make a call using it.
	// httpResp, err := r.client.Do(httpReq)
	// if err != nil {
	//     resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read Argon2, got error: %s", err))
	//     return
	// }

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *Argon2Resource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var (
		data    Argon2ResourceModel
		oldData Argon2ResourceModel
	)

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(req.State.Get(ctx, &oldData)...)

	if oldData.Password.Equal(data.Password) {
		data.Hash = oldData.Hash
	} else {
		digest := generatePassword(resp.Diagnostics, data)
		if digest == nil {
			return
		}
		data.Hash = types.StringValue(digest.String())
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *Argon2Resource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data Argon2ResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *Argon2Resource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
