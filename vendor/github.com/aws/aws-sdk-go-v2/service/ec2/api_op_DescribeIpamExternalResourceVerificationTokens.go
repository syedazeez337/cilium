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

// Describe verification tokens. A verification token is an Amazon Web
// Services-generated random value that you can use to prove ownership of an
// external resource. For example, you can use a verification token to validate
// that you control a public IP address range when you bring an IP address range to
// Amazon Web Services (BYOIP).
func (c *Client) DescribeIpamExternalResourceVerificationTokens(ctx context.Context, params *DescribeIpamExternalResourceVerificationTokensInput, optFns ...func(*Options)) (*DescribeIpamExternalResourceVerificationTokensOutput, error) {
	if params == nil {
		params = &DescribeIpamExternalResourceVerificationTokensInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "DescribeIpamExternalResourceVerificationTokens", params, optFns, c.addOperationDescribeIpamExternalResourceVerificationTokensMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*DescribeIpamExternalResourceVerificationTokensOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DescribeIpamExternalResourceVerificationTokensInput struct {

	// A check for whether you have the required permissions for the action without
	// actually making the request and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation . Otherwise, it is
	// UnauthorizedOperation .
	DryRun *bool

	// One or more filters for the request. For more information about filtering, see [Filtering CLI output].
	//
	// Available filters:
	//
	//   - ipam-arn
	//
	//   - ipam-external-resource-verification-token-arn
	//
	//   - ipam-external-resource-verification-token-id
	//
	//   - ipam-id
	//
	//   - ipam-region
	//
	//   - state
	//
	//   - status
	//
	//   - token-name
	//
	//   - token-value
	//
	// [Filtering CLI output]: https://docs.aws.amazon.com/cli/latest/userguide/cli-usage-filter.html
	Filters []types.Filter

	// Verification token IDs.
	IpamExternalResourceVerificationTokenIds []string

	// The maximum number of tokens to return in one page of results.
	MaxResults *int32

	// The token for the next page of results.
	NextToken *string

	noSmithyDocumentSerde
}

type DescribeIpamExternalResourceVerificationTokensOutput struct {

	// Verification tokens.
	IpamExternalResourceVerificationTokens []types.IpamExternalResourceVerificationToken

	// The token to use to retrieve the next page of results. This value is null when
	// there are no more results to return.
	NextToken *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationDescribeIpamExternalResourceVerificationTokensMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsEc2query_serializeOpDescribeIpamExternalResourceVerificationTokens{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpDescribeIpamExternalResourceVerificationTokens{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "DescribeIpamExternalResourceVerificationTokens"); err != nil {
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
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opDescribeIpamExternalResourceVerificationTokens(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opDescribeIpamExternalResourceVerificationTokens(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "DescribeIpamExternalResourceVerificationTokens",
	}
}
