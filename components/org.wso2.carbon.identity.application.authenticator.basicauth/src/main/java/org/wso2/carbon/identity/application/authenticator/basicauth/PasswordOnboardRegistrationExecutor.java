/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.basicauth;

import org.wso2.carbon.identity.user.self.registration.action.AttributeCollection;
import org.wso2.carbon.identity.user.self.registration.action.Authentication;
import org.wso2.carbon.identity.user.self.registration.action.CredentialEnrollment;
import org.wso2.carbon.identity.user.self.registration.model.ExecutorResponse;
import org.wso2.carbon.identity.user.self.registration.model.InitData;
import org.wso2.carbon.identity.user.self.registration.model.InputMetaData;
import org.wso2.carbon.identity.user.self.registration.model.RegistrationContext;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.user.self.registration.util.Constants.STATUS_ACTION_COMPLETE;
import static org.wso2.carbon.identity.user.self.registration.util.Constants.STATUS_ATTR_REQUIRED;
import static org.wso2.carbon.identity.user.self.registration.util.Constants.STATUS_CRED_REQUIRED;

public class PasswordOnboardRegistrationExecutor implements Authentication, AttributeCollection, CredentialEnrollment {

    public String getName() {

        return "PasswordOnboard";
    }

    @Override
    public ExecutorResponse authenticate(Map<String, String> input, RegistrationContext context) {

        return null;
    }

    @Override
    public ExecutorResponse collect(Map<String, String> input, RegistrationContext context) {

        // Implement the actual task logic here
        if (input != null && !input.isEmpty() && input.containsKey("username")) {
            // Store the email address in the context
            // Update the required data
            return new ExecutorResponse("COMPLETE");
        }
        ExecutorResponse executorResponse = new ExecutorResponse("ATTRIBUTES_REQUIRED");
        executorResponse.setRequiredData(getUsernameData());
        return executorResponse;
    }

    @Override
    public ExecutorResponse enrollCredential(Map<String, String> input, RegistrationContext context) {

        // Implement the actual task logic here
        if (input != null && !input.isEmpty() && input.containsKey("password")) {
            // Validate OTP
            return new ExecutorResponse(STATUS_ACTION_COMPLETE);
        }

        ExecutorResponse executorResponse = new ExecutorResponse(STATUS_CRED_REQUIRED);
        executorResponse.setRequiredData(getPasswordData());
        return executorResponse;
    }

    @Override
    public List<InitData> getInitData() {

        List<InitData> response = new ArrayList<>();
        response.add(getAttrCollectInitData());
        response.add(getCredentialEnrollmentInitData());
        return response;
    }

    @Override
    public InitData getCredentialEnrollmentInitData() {

        return new InitData(STATUS_CRED_REQUIRED, getPasswordData());
    }

    @Override
    public InitData getAuthInitData() {

        List<InputMetaData> inputMetaData = new ArrayList<>();
        inputMetaData.addAll(getUsernameData());
        inputMetaData.addAll(getPasswordData());
        return new InitData("AUTH_REQUIRED", inputMetaData);
    }

    @Override
    public InitData getAttrCollectInitData() {

        return new InitData(STATUS_ATTR_REQUIRED, getUsernameData());
    }

    private List<InputMetaData> getUsernameData() {

        // Define a new list of InputMetaData and add the data object and return the list.
        List<InputMetaData> inputMetaData = new ArrayList<>();
        InputMetaData e1 = new InputMetaData("username", "attribute", 1);
        e1.setMandatory(true);
        e1.setValidationRegex("*");
        inputMetaData.add(e1);
        return inputMetaData;
    }

    private List<InputMetaData> getPasswordData() {

        List<InputMetaData> inputMetaData = new ArrayList<>();
        InputMetaData e2 = new InputMetaData("password", "credential", 1);
        e2.setMandatory(true);
        e2.setValidationRegex("^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d]{8,}$");
        inputMetaData.add(e2);
        return inputMetaData;
    }
}