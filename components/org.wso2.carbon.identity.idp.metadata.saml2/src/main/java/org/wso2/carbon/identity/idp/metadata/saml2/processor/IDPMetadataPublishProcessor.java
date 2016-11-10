/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.idp.metadata.saml2.processor;

import org.wso2.carbon.identity.idp.metadata.saml2.bean.SAMLMetadataResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.idp.metadata.saml2.bean.SAMLMetadataErrorResponse;
import org.wso2.carbon.identity.idp.metadata.saml2.internal.IDPMetadataSAMLServiceComponentHolder;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;


/**
 * This class implements functionality to set metadata content to SAML2MetadataResponseBuilder
 */

public class IDPMetadataPublishProcessor extends IdentityProcessor {
    private static Log log = LogFactory.getLog(IDPMetadataPublishProcessor.class);
    private String relyingParty;

    @Override
    public String getName() {
        return "IDPMetadataPublishProcessor";
    }

    @Override
    public int getPriority() {
        return 2;
    }

    @Override
    public String getCallbackPath(IdentityMessageContext context) {
        return IdentityUtil.getServerURL("identity", false, false);
    }

    @Override
    public String getRelyingPartyId() {
        return this.relyingParty;
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        if (identityRequest.getPathInfo().contains("/metadata/saml2")) {
            return true;
        } else {
            return false;
        }
    }

    public IdentityResponse.IdentityResponseBuilder process(IdentityRequest identityRequest) throws
            FrameworkException {

        String tennantDomain = identityRequest.getTenantDomain();
        IdentityProviderManager identityProviderManager = (IdentityProviderManager) IDPMetadataSAMLServiceComponentHolder.getInstance().getIdpManager();
        String metadata = null;
        try {
            metadata = identityProviderManager.getResidentIDPMetadata(tennantDomain);
        } catch (IdentityProviderManagementException ex) {
            IdentityMessageContext context = new IdentityMessageContext(identityRequest);
            SAMLMetadataErrorResponse.SAMLMetadataErrorResponseBuilder responseBuilder = new SAMLMetadataErrorResponse.SAMLMetadataErrorResponseBuilder(context);
            responseBuilder.setMessage("Internal Server Error");
            return responseBuilder;

        }
        IdentityMessageContext context = new IdentityMessageContext(identityRequest);
        SAMLMetadataResponse.SAMLMetadataResponseBuilder responseBuilder = new SAMLMetadataResponse.SAMLMetadataResponseBuilder(context);
        responseBuilder.setMetadata(metadata);
        return responseBuilder;

    }


}