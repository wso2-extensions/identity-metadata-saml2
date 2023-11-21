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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.idp.metadata.saml2.bean.SAMLMetadataErrorResponse;
import org.wso2.carbon.identity.idp.metadata.saml2.bean.SAMLMetadataResponse;
import org.wso2.carbon.identity.idp.metadata.saml2.internal.IDPMetadataSAMLServiceComponentHolder;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

/**
 * This class implements functionality to set metadata content to SAML2MetadataResponseBuilder.
 */
public class IDPMetadataPublishProcessor extends IdentityProcessor {

    private static final Log log = LogFactory.getLog(IDPMetadataPublishProcessor.class);
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
    public String getRelyingPartyId(IdentityMessageContext identityMessageContext) {

        return getRelyingPartyId();
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {

        return identityRequest.getRequestURI().contains("/metadata/saml2");
    }

    public IdentityResponse.IdentityResponseBuilder process(IdentityRequest identityRequest) throws
            FrameworkException {

        String tenantDomain = identityRequest.getTenantDomain();
        try {
            if (OrganizationManagementUtil.isOrganization(tenantDomain)) {
                tenantDomain = resolveRootTenantDomain(tenantDomain);
            }
        } catch (OrganizationManagementException e) {
            log.error("Error while checking the tenant: " + tenantDomain + " is an organization.", e);
        }
        IdentityProviderManager identityProviderManager = (IdentityProviderManager)
                IDPMetadataSAMLServiceComponentHolder.getInstance().getIdpManager();
        String metadata;
        try {
            if (log.isDebugEnabled()) {
                log.debug("Starting to retrieve resident IdP metadata for tenant: " + tenantDomain);
            }
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain, true);
            metadata = identityProviderManager.getResidentIDPMetadata(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            log.error("Internal Server Error", e);
            IdentityMessageContext context = new IdentityMessageContext(identityRequest);
            SAMLMetadataErrorResponse.SAMLMetadataErrorResponseBuilder responseBuilder =
                    new SAMLMetadataErrorResponse.SAMLMetadataErrorResponseBuilder(context);
            responseBuilder.setMessage("Internal Server Error");
            return responseBuilder;

        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
        IdentityMessageContext context = new IdentityMessageContext(identityRequest);
        SAMLMetadataResponse.SAMLMetadataResponseBuilder responseBuilder =
                new SAMLMetadataResponse.SAMLMetadataResponseBuilder(context);
        responseBuilder.setMetadata(metadata);
        return responseBuilder;

    }

    private String resolveRootTenantDomain(String tenantDomain) {

        try {
            String organizationId = IDPMetadataSAMLServiceComponentHolder.getInstance().getOrganizationManager()
                    .resolveOrganizationId(tenantDomain);
            String rootOrganizationId = IDPMetadataSAMLServiceComponentHolder.getInstance().getOrganizationManager()
                    .getPrimaryOrganizationId(organizationId);
            return IDPMetadataSAMLServiceComponentHolder.getInstance().getOrganizationManager()
                    .resolveTenantDomain(rootOrganizationId);
        } catch (OrganizationManagementException e) {
            log.error("Error while resolving the root tenant domain of the tenant: " + tenantDomain, e);
            return tenantDomain;
        }
    }
}
