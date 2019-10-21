// Copyright 2018 Comcast Cable Communications Management, LLC
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	khcheck "github.com/Comcast/kuberhealthy/pkg/khcheckcrd"
	log "github.com/sirupsen/logrus"

	// khcheck "github.com/Comcast/kuberhealthy/pkg/khcheckcrd"
	v1 "k8s.io/api/admission/v1"
	"k8s.io/api/admission/v1beta1"
)

// mutateHandlerWrapper
func mutateHandlerWrapper() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := mutate(w, r)
		if err != nil {
			log.Errorln("error occurred during mutation:", err)
		}
	})
}

// mutate
func mutate(w http.ResponseWriter, r *http.Request) error {

	log.Infoln("Handling mutation webhook request.")

	b, err := performMutation(w, r)
	if err != nil {
		err = fmt.Errorf("failed to perform admission mutation: %w", err)
		return err
	}

	_, err = w.Write(b)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		err = fmt.Errorf("failed to write byte slice to response.: %w", err)
		return err
	}

	return nil
}

// performMutate
func performMutation(w http.ResponseWriter, r *http.Request) ([]byte, error) {

	log.Infoln("Performing mutation.")

	// Only handle POST requests with a body and json content type.
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil, fmt.Errorf("invalid method %s, only %s requests are allowed", r.Method, http.MethodPost)
	}

	// Only handle json/application requests.
	if r.Header.Get(httpHeaderContentType) != contentTypeJSON {
		w.WriteHeader(http.StatusBadRequest)
		return nil, fmt.Errorf("unsupported content type %s, only %s is supported", r.Header.Get(httpHeaderContentType), contentTypeJSON)
	}

	// Read the request.
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return nil, fmt.Errorf("could not read admission request body: %v", err)
	}

	// Parse the admission review request.
	var admissionReviewRequest v1.AdmissionReview
	_, _, err = deserializer.Decode(body, nil, &admissionReviewRequest)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return nil, fmt.Errorf("could not decode admission request: %w", err)
	}
	if admissionReviewRequest.Request == nil {
		w.WriteHeader(http.StatusBadRequest)
		return nil, fmt.Errorf("malformed admission request -- request is %v", admissionReviewRequest.Request)
	}

	// Construct the admission review response.
	admissionReviewResponse := v1.AdmissionReview{
		Response: &v1.AdmissionResponse{
			UID: admissionReviewRequest.Request.UID,
		},
	}

	// Fail the request if it is not a KHCheckCRD.
	if admissionReviewRequest.Request.Resource != khcheckCRDResource {
		w.WriteHeader(http.StatusBadRequest)
		return nil, fmt.Errorf("expected resource to be %s", khcheckCRDResource)
	}

	// Parse the KHCheck object.
	rawKHCheck := admissionReviewRequest.Request.Object.Raw
	khCheck := &khcheck.KuberhealthyCheck{}
	_, _, err = deserializer.Decode(rawKHCheck, nil, khCheck)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return nil, fmt.Errorf("could not decode khcheck: %w", err)
	}

	// Mutate the KHCheck.
	patch, err := mutateKHCheck(khCheck)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return nil, fmt.Errorf("could not validate khcheck: %w", err)
	}

	// Admit the review if there was no error.
	// Also admit the patch for the KHCheckCRD.
	admissionReviewResponse.Response.Allowed = true
	jsonPatchType := v1.PatchTypeJSONPatch
	admissionReviewResponse.Response.PatchType = &jsonPatchType
	admissionReviewResponse.Response.Patch = patch

	// Return the admission review with a response as JSON.
	// admissionReviewRequest.Request.Object = &khCheck
	bytes, err := json.Marshal(&admissionReviewResponse)
	if err != nil {
		return nil, fmt.Errorf("marshaling response: %v", err)
	}
	log.Infoln("Completed mutation.")
	return bytes, nil
}

// mutateKHCheck
func mutateKHCheck(check *khcheck.KuberhealthyCheck) ([]byte, error) {

	if check == nil {
		return nil, fmt.Errorf("check given to mutate func is nil: %v", check)
	}

	// if check.Name == "" {
	// 	log.Warnln("Check name is empty.")
	// }

	// if check.Namespace == "" {
	// 	log.Warnln("Check namespace is empty.")
	// }

	// for _, container := range check.Spec.PodSpec.Containers {
	// 	if container.
	// }

	return nil, nil
}

// validateHandlerWrapper
func validateHandlerWrapper() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := validate(w, r)
		if err != nil {
			log.Errorln("error occurred during validation:", err)
		}
	})
}

// validate
func validate(w http.ResponseWriter, r *http.Request) error {

	log.Infoln("Handling validation webhook request.")

	b, err := performValidation(w, r)
	if err != nil {
		err = fmt.Errorf("failed to perform admission validation: %w", err)
		return err
	}

	_, err = w.Write(b)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		err = fmt.Errorf("failed to write byte slice to response.: %w", err)
		return err
	}

	return nil
}

// performValidation
func performValidation(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	log.Infoln("Performing validation.")

	// Only handle POST requests with a body and json content type.
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil, fmt.Errorf("invalid method %s, only %s requests are allowed", r.Method, http.MethodPost)
	}

	// Only handle json/application requests.
	if r.Header.Get(httpHeaderContentType) != contentTypeJSON {
		w.WriteHeader(http.StatusBadRequest)
		return nil, fmt.Errorf("unsupported content type %s, only %s is supported", r.Header.Get(httpHeaderContentType), contentTypeJSON)
	}

	// Read the request.
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return nil, fmt.Errorf("could not read admission request body: %v", err)
	}

	// Parse the admission review request.
	var admissionReviewRequest v1beta1.AdmissionReview
	_, _, err = deserializer.Decode(body, nil, &admissionReviewRequest)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return nil, fmt.Errorf("could not decode admission request: %w", err)
	}
	if admissionReviewRequest.Request == nil {
		w.WriteHeader(http.StatusBadRequest)
		return nil, fmt.Errorf("malformed admission request -- request is %v", admissionReviewRequest.Request)
	}

	// Construct the admission review response.
	admissionReviewResponse := v1beta1.AdmissionReview{
		Response: &v1beta1.AdmissionResponse{
			UID: admissionReviewRequest.Request.UID,
		},
	}

	// Fail the request if it is not a KHCheckCRD.
	if admissionReviewRequest.Request.Resource != khcheckCRDResource {
		w.WriteHeader(http.StatusBadRequest)
		return nil, fmt.Errorf("expected resource to be %s", khcheckCRDResource)
	}

	// Parse the KHCheck object.
	rawKHCheck := admissionReviewRequest.Request.Object.Raw
	khCheck := &khcheck.KuberhealthyCheck{}
	_, _, err = deserializer.Decode(rawKHCheck, nil, khCheck)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return nil, fmt.Errorf("could not decode khcheck: %w", err)
	}

	// Mutate the KHCheck.
	err = validateKHCheck(khCheck)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return nil, fmt.Errorf("could not validate khcheck: %w", err)
	}

	// Return the admission review with a response as JSON.
	// admissionReviewRequest.Request.Object = &khCheck
	bytes, err := json.Marshal(&admissionReviewResponse)
	if err != nil {
		return nil, fmt.Errorf("marshaling response: %v", err)
	}
	log.Infoln("Completed mutation.")
	return bytes, nil
}

// validateKHCheck
func validateKHCheck(check *khcheck.KuberhealthyCheck) error {
	if check == nil {
		return fmt.Errorf("check given to validate func is nil: %v", check)
	}
	return nil
}
