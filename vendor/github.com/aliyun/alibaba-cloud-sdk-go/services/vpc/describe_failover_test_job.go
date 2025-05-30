package vpc

//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
//
// Code generated by Alibaba Cloud SDK Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

import (
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/responses"
)

// DescribeFailoverTestJob invokes the vpc.DescribeFailoverTestJob API synchronously
func (client *Client) DescribeFailoverTestJob(request *DescribeFailoverTestJobRequest) (response *DescribeFailoverTestJobResponse, err error) {
	response = CreateDescribeFailoverTestJobResponse()
	err = client.DoAction(request, response)
	return
}

// DescribeFailoverTestJobWithChan invokes the vpc.DescribeFailoverTestJob API asynchronously
func (client *Client) DescribeFailoverTestJobWithChan(request *DescribeFailoverTestJobRequest) (<-chan *DescribeFailoverTestJobResponse, <-chan error) {
	responseChan := make(chan *DescribeFailoverTestJobResponse, 1)
	errChan := make(chan error, 1)
	err := client.AddAsyncTask(func() {
		defer close(responseChan)
		defer close(errChan)
		response, err := client.DescribeFailoverTestJob(request)
		if err != nil {
			errChan <- err
		} else {
			responseChan <- response
		}
	})
	if err != nil {
		errChan <- err
		close(responseChan)
		close(errChan)
	}
	return responseChan, errChan
}

// DescribeFailoverTestJobWithCallback invokes the vpc.DescribeFailoverTestJob API asynchronously
func (client *Client) DescribeFailoverTestJobWithCallback(request *DescribeFailoverTestJobRequest, callback func(response *DescribeFailoverTestJobResponse, err error)) <-chan int {
	result := make(chan int, 1)
	err := client.AddAsyncTask(func() {
		var response *DescribeFailoverTestJobResponse
		var err error
		defer close(result)
		response, err = client.DescribeFailoverTestJob(request)
		callback(response, err)
		result <- 1
	})
	if err != nil {
		defer close(result)
		callback(nil, err)
		result <- 0
	}
	return result
}

// DescribeFailoverTestJobRequest is the request struct for api DescribeFailoverTestJob
type DescribeFailoverTestJobRequest struct {
	*requests.RpcRequest
	ClientToken          string           `position:"Query" name:"ClientToken"`
	JobId                string           `position:"Query" name:"JobId"`
	ResourceOwnerAccount string           `position:"Query" name:"ResourceOwnerAccount"`
	OwnerAccount         string           `position:"Query" name:"OwnerAccount"`
	OwnerId              requests.Integer `position:"Query" name:"OwnerId"`
}

// DescribeFailoverTestJobResponse is the response struct for api DescribeFailoverTestJob
type DescribeFailoverTestJobResponse struct {
	*responses.BaseResponse
	RequestId            string               `json:"RequestId" xml:"RequestId"`
	FailoverTestJobModel FailoverTestJobModel `json:"FailoverTestJobModel" xml:"FailoverTestJobModel"`
}

// CreateDescribeFailoverTestJobRequest creates a request to invoke DescribeFailoverTestJob API
func CreateDescribeFailoverTestJobRequest() (request *DescribeFailoverTestJobRequest) {
	request = &DescribeFailoverTestJobRequest{
		RpcRequest: &requests.RpcRequest{},
	}
	request.InitWithApiInfo("Vpc", "2016-04-28", "DescribeFailoverTestJob", "vpc", "openAPI")
	request.Method = requests.POST
	return
}

// CreateDescribeFailoverTestJobResponse creates a response to parse from DescribeFailoverTestJob response
func CreateDescribeFailoverTestJobResponse() (response *DescribeFailoverTestJobResponse) {
	response = &DescribeFailoverTestJobResponse{
		BaseResponse: &responses.BaseResponse{},
	}
	return
}
