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

import org.wso2.carbon.identity.user.registration.RegistrationStepExecutor;
import org.wso2.carbon.identity.user.registration.config.RegistrationStepExecutorConfig;
import org.wso2.carbon.identity.user.registration.exception.RegistrationFrameworkException;
import org.wso2.carbon.identity.user.registration.model.RegistrationContext;
import org.wso2.carbon.identity.user.registration.model.RegistrationRequestedUser;
import org.wso2.carbon.identity.user.registration.model.response.ExecutorMetadata;
import org.wso2.carbon.identity.user.registration.model.response.ExecutorResponse;
import org.wso2.carbon.identity.user.registration.model.response.Message;
import org.wso2.carbon.identity.user.registration.model.response.NextStepResponse;
import org.wso2.carbon.identity.user.registration.model.response.RequiredParam;
import org.wso2.carbon.identity.user.registration.util.RegistrationFlowConstants;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.user.registration.util.RegistrationFlowConstants.StepStatus.COMPLETE;
import static org.wso2.carbon.identity.user.registration.util.RegistrationFlowConstants.StepStatus.NOT_STARTED;
import static org.wso2.carbon.identity.user.registration.util.RegistrationFlowConstants.StepStatus.USER_INPUT_REQUIRED;

public class PasswordOnboardRegistrationExecutor implements RegistrationStepExecutor {

    private static PasswordOnboardRegistrationExecutor instance = new PasswordOnboardRegistrationExecutor();
    private static final String PASSWORD = "password";
    private static final String USERNAME_URI = "http://wso2.org/claims/username";

    public static PasswordOnboardRegistrationExecutor getInstance() {

        return instance;
    }

    @Override
    public String getName() {

        return "PasswordOnboarding";
    }

    @Override
    public RegistrationFlowConstants.RegistrationExecutorBindingType getBindingType() throws RegistrationFrameworkException {

        return RegistrationFlowConstants.RegistrationExecutorBindingType.AUTHENTICATOR;
    }

    @Override
    public String getBoundIdentifier() throws RegistrationFrameworkException {

        return BasicAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public String getExecutorType() throws RegistrationFrameworkException {

        return RegistrationFlowConstants.RegistrationExecutorType.CREDENTIAL.toString();
    }

    @Override
    public List<RequiredParam> getRequiredParams() {

        List<RequiredParam> params = new ArrayList<>();

        RequiredParam param1 = new RequiredParam();
        param1.setName(USERNAME_URI);
        param1.setAvailableValue(null);
        param1.setConfidential(false);
        param1.setMandatory(true);
        params.add(param1);

        RequiredParam param2 = new RequiredParam();
        param2.setName(PASSWORD);
        param2.setAvailableValue(null);
        param2.setConfidential(true);
        param2.setMandatory(true);
        params.add(param2);

        return params;
    }

    @Override
    public RegistrationFlowConstants.StepStatus execute(Map<String, String> inputs, RegistrationContext context,
                                                        NextStepResponse response,
                                                        RegistrationStepExecutorConfig config) throws RegistrationFrameworkException {

        RegistrationFlowConstants.StepStatus status = context.getCurrentStepStatus();
        RegistrationRequestedUser user = context.getRegisteringUser();

        if (NOT_STARTED.equals(status)) {
            Message message = new Message();
            message.setType(RegistrationFlowConstants.MessageType.INFO);

            List<RequiredParam> requiredParams = this.getRequiredParams();

            if (user.getUsername() == null) {
                message.setMessage("Onboard username and password");
            } else {
                // Username is already defined. No need to prompt for username again. Prompt only the password.
                message.setMessage("Onboard password");
                requiredParams = this.getRequiredParams().subList(1, 1);
            }
            updateResponse(response, config, requiredParams, message);
            context.updateRequestedParameterList(this.getRequiredParams());
            return USER_INPUT_REQUIRED;
        } else if (USER_INPUT_REQUIRED.equals(status)) {
            return processInput(inputs, context);
        } else {
            throw new RegistrationFrameworkException("Unsupported step status");
        }
    }

    private void updateResponse(NextStepResponse response, RegistrationStepExecutorConfig config,
                                List<RequiredParam> params, Message message) {

        ExecutorResponse executorResponse = new ExecutorResponse();
        executorResponse.setName(config.getName());
        executorResponse.setExecutorName(this.getName());
        executorResponse.setId(config.getId());

        ExecutorMetadata metadata = new ExecutorMetadata();
        metadata.setI18nKey("executor.passwordOnboarding");
        metadata.setPromptType(RegistrationFlowConstants.PromptType.USER_PROMPT);
        metadata.setRequiredParams(params);
        executorResponse.setMetadata(metadata);

        response.addExecutor(executorResponse);
        response.addMessage(message);
    }

    private RegistrationFlowConstants.StepStatus processInput(Map<String, String> inputs,
                                                              RegistrationContext context) throws RegistrationFrameworkException {

        RegistrationRequestedUser user = context.getRegisteringUser();

//        for (RequiredParam param : context.getRequestedParameters()) {
//            if (inputs.get(param.getName()) == null) {
//                throw new RegistrationFrameworkException(param.getName() + " is not set as expected in the step.");
//            }
//            if (param.getName().equals(USERNAME_URI)) {
//                user.setUsername(inputs.get(USERNAME_URI));
//            } else if (param.getName().equals(PASSWORD)) {
//                user.setPasswordless(false);
//                user.setCredential(inputs.get(PASSWORD));            }
//        }
        for (String key : inputs.keySet()) {
            if (key.equals(USERNAME_URI)) {
                user.setUsername(inputs.get(USERNAME_URI));
            } else if (key.equals(PASSWORD)) {
                user.setPasswordless(false);
                user.setCredential(inputs.get(PASSWORD));
            }
        }

            return COMPLETE;
    }
}
