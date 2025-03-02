// Code generated by smithy-go-codegen DO NOT EDIT.

package ec2

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Describes the specified attribute of the specified instance. You can specify
// only one attribute at a time.
func (c *Client) DescribeInstanceAttribute(ctx context.Context, params *DescribeInstanceAttributeInput, optFns ...func(*Options)) (*DescribeInstanceAttributeOutput, error) {
	if params == nil {
		params = &DescribeInstanceAttributeInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DescribeInstanceAttribute", params, optFns, c.addOperationDescribeInstanceAttributeMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DescribeInstanceAttributeOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DescribeInstanceAttributeInput struct {

	// The instance attribute.
	//
	// Note that the enaSupport attribute is not supported.
	//
	// This member is required.
	Attribute types.InstanceAttributeName

	// The ID of the instance.
	//
	// This member is required.
	InstanceId *string

	// Checks whether you have the required permissions for the operation, without
	// actually making the request, and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation . Otherwise, it is
	// UnauthorizedOperation .
	DryRun *bool

	noSmithyDocumentSerde
}

// Describes an instance attribute.
type DescribeInstanceAttributeOutput struct {

	// The block device mapping of the instance.
	BlockDeviceMappings []types.InstanceBlockDeviceMapping

	// Indicates whether stop protection is enabled for the instance.
	DisableApiStop *types.AttributeBooleanValue

	// Indicates whether termination protection is enabled. If the value is true , you
	// can't terminate the instance using the Amazon EC2 console, command line tools,
	// or API.
	DisableApiTermination *types.AttributeBooleanValue

	// Indicates whether the instance is optimized for Amazon EBS I/O.
	EbsOptimized *types.AttributeBooleanValue

	// Indicates whether enhanced networking with ENA is enabled.
	EnaSupport *types.AttributeBooleanValue

	// Indicates whether the instance is enabled for Amazon Web Services Nitro
	// Enclaves.
	EnclaveOptions *types.EnclaveOptions

	// The security groups associated with the instance.
	Groups []types.GroupIdentifier

	// The ID of the instance.
	InstanceId *string

	// Indicates whether an instance stops or terminates when you initiate shutdown
	// from the instance (using the operating system command for system shutdown).
	InstanceInitiatedShutdownBehavior *types.AttributeValue

	// The instance type.
	InstanceType *types.AttributeValue

	// The kernel ID.
	KernelId *types.AttributeValue

	// The product codes.
	ProductCodes []types.ProductCode

	// The RAM disk ID.
	RamdiskId *types.AttributeValue

	// The device name of the root device volume (for example, /dev/sda1 ).
	RootDeviceName *types.AttributeValue

	// Indicates whether source/destination checks are enabled.
	SourceDestCheck *types.AttributeBooleanValue

	// Indicates whether enhanced networking with the Intel 82599 Virtual Function
	// interface is enabled.
	SriovNetSupport *types.AttributeValue

	// The user data.
	UserData *types.AttributeValue

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDescribeInstanceAttributeMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsEc2query_serializeOpDescribeInstanceAttribute{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpDescribeInstanceAttribute{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "DescribeInstanceAttribute"); err != nil {
		return fmt.Errorf("add protocol finalizers: %v", err)
	}

	if err = addlegacyEndpointContextSetter(stack, options); err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = addClientRequestID(stack); err != nil {
		return err
	}
	if err = addComputeContentLength(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = addComputePayloadSHA256(stack); err != nil {
		return err
	}
	if err = addRetry(stack, options); err != nil {
		return err
	}
	if err = addRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = addRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addSpanRetryLoop(stack, options); err != nil {
		return err
	}
	if err = addClientUserAgent(stack, options); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addSetLegacyContextSigningOptionsMiddleware(stack); err != nil {
		return err
	}
	if err = addTimeOffsetBuild(stack, c); err != nil {
		return err
	}
	if err = addUserAgentRetryMode(stack, options); err != nil {
		return err
	}
	if err = addCredentialSource(stack, options); err != nil {
		return err
	}
	if err = addOpDescribeInstanceAttributeValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDescribeInstanceAttribute(options.Region), middleware.Before); err != nil {
		return err
	}
	if err = addRecursionDetection(stack); err != nil {
		return err
	}
	if err = addRequestIDRetrieverMiddleware(stack); err != nil {
		return err
	}
	if err = addResponseErrorMiddleware(stack); err != nil {
		return err
	}
	if err = addRequestResponseLogging(stack, options); err != nil {
		return err
	}
	if err = addDisableHTTPSMiddleware(stack, options); err != nil {
		return err
	}
	if err = addSpanInitializeStart(stack); err != nil {
		return err
	}
	if err = addSpanInitializeEnd(stack); err != nil {
		return err
	}
	if err = addSpanBuildRequestStart(stack); err != nil {
		return err
	}
	if err = addSpanBuildRequestEnd(stack); err != nil {
		return err
	}
	return nil
}

func newServiceMetadataMiddleware_opDescribeInstanceAttribute(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "DescribeInstanceAttribute",
	}
}
