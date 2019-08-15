/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.idp.metadata.saml2.builder;

import org.apache.commons.lang.StringUtils;
import org.joda.time.DateTime;

//import org.opensaml.saml2.metadata.EntityDescriptor; Previous Version (New Version Below)
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

//import org.opensaml.saml2.metadata.IDPSSODescriptor; Previous Version (New Version Below)
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;

//import org.opensaml.saml2.metadata.SingleSignOnService; Previous Version (New Version Below)
import org.opensaml.saml.saml2.metadata.SingleSignOnService;

import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.idp.metadata.saml2.ConfigElements;
import org.wso2.carbon.identity.idp.metadata.saml2.IDPMetadataConstant;
import org.wso2.carbon.identity.idp.metadata.saml2.util.BuilderUtil;
import org.wso2.carbon.idp.mgt.MetadataException;

import java.util.ArrayList;
import java.util.List;

/**
 * This class defines methods that are used to convert a metadata String using saml2SSOFederatedAuthenticatedConfig
 */
public abstract class IDPMetadataBuilder extends AbstractIdentityHandler {

    static final long ONE_MINUTE_IN_MILLIS=60000;

    private boolean samlMetadataSigningEnabled;

    private boolean wantAuthRequestSigned;

    public String build(FederatedAuthenticatorConfig samlFederatedAuthenticatorConfig) throws MetadataException {


        EntityDescriptor entityDescriptor = buildEntityDescriptor(samlFederatedAuthenticatorConfig);
        IDPSSODescriptor idpSsoDesc = buildIDPSSODescriptor();
        setValidityPeriod(idpSsoDesc, samlFederatedAuthenticatorConfig);
        buildSupportedProtocol(idpSsoDesc);
        buildSingleSignOnService(idpSsoDesc, samlFederatedAuthenticatorConfig);
        String samlSsoURL =  getFederatedAuthenticatorConfigProperty(samlFederatedAuthenticatorConfig,
                IdentityApplicationConstants.Authenticator.SAML2SSO.SSO_URL).getValue();
        for (Property property : samlFederatedAuthenticatorConfig.getProperties()) {
            if (StringUtils.equals(samlSsoURL, property.getValue())) {
                continue; // Skip since default SSO URL has been already added
            }
            if (StringUtils.startsWith(property.getName(), IdentityApplicationConstants.Authenticator.SAML2SSO.
                    DESTINATION_URL_PREFIX)) {

                SingleSignOnService ssoHTTPPost = BuilderUtil
                        .createSAMLObject(ConfigElements.FED_METADATA_NS, ConfigElements.SSOSERVICE_DESCRIPTOR, "");
                ssoHTTPPost.setBinding(IDPMetadataConstant.HTTP_BINDING_POST_SAML2);
                ssoHTTPPost.setLocation(property.getValue());
                idpSsoDesc.getSingleSignOnServices().add(ssoHTTPPost);

                SingleSignOnService ssoHTTPRedirect = BuilderUtil
                        .createSAMLObject(ConfigElements.FED_METADATA_NS, ConfigElements.SSOSERVICE_DESCRIPTOR, "");
                ssoHTTPRedirect.setBinding(IDPMetadataConstant.HTTP_BINDING_REDIRECT_SAML2);
                ssoHTTPRedirect.setLocation(property.getValue());
                idpSsoDesc.getSingleSignOnServices().add(ssoHTTPRedirect);
            }
        }
        buildNameIdFormat(idpSsoDesc);
        buildSingleLogOutService(idpSsoDesc, samlFederatedAuthenticatorConfig);
        buildArtifactResolutionService(idpSsoDesc, samlFederatedAuthenticatorConfig);
        entityDescriptor.getRoleDescriptors().add(idpSsoDesc);
        buildKeyDescriptor(entityDescriptor);
        buildExtensions(idpSsoDesc);
        idpSsoDesc.setWantAuthnRequestsSigned(wantAuthRequestSigned);
        setSamlMetadataSigningEnabled(samlFederatedAuthenticatorConfig);

        return marshallDescriptor(entityDescriptor);
    }

    private FederatedAuthenticatorConfig getSAMLFederatedAuthenticatorConfig(IdentityProvider identityProvider) {
        for (FederatedAuthenticatorConfig config : identityProvider.getFederatedAuthenticatorConfigs()) {
            if (IdentityApplicationConstants.Authenticator.SAML2SSO.NAME.equals(config.getName())) {
                return config;
            }
        }
        return null;
    }

    private Property getFederatedAuthenticatorConfigProperty(
            FederatedAuthenticatorConfig samlFederatedAuthenticatorConfig, String name) {
        Property[] properties = samlFederatedAuthenticatorConfig.getProperties();
        if (properties != null) {
            for (Property property : properties) {
                if (name != null && property != null && name.equals(property.getName())) {
                    return property;
                }
            }
        }
        return null;
    }


    protected abstract EntityDescriptor buildEntityDescriptor(FederatedAuthenticatorConfig samlFederatedAuthenticatorConfig) throws MetadataException;

    protected abstract IDPSSODescriptor buildIDPSSODescriptor() throws MetadataException;

    protected abstract void buildValidityPeriod(IDPSSODescriptor idpSsoDesc) throws MetadataException;

    protected abstract void buildSupportedProtocol(IDPSSODescriptor idpSsoDesc) throws MetadataException;

    protected abstract void buildKeyDescriptor(EntityDescriptor entityDescriptor) throws MetadataException;

    protected abstract void buildNameIdFormat(IDPSSODescriptor idpSsoDesc) throws MetadataException;

    protected abstract void buildSingleSignOnService(IDPSSODescriptor idpSsoDesc, FederatedAuthenticatorConfig samlFederatedAuthenticatorConfig) throws MetadataException;

    protected abstract void buildSingleLogOutService(IDPSSODescriptor idpSsoDesc, FederatedAuthenticatorConfig samlFederatedAuthenticatorConfig) throws MetadataException;

    protected abstract void buildArtifactResolutionService(IDPSSODescriptor idpSsoDesc, FederatedAuthenticatorConfig samlFederatedAuthenticatorConfig) throws MetadataException;

    protected abstract void buildExtensions(IDPSSODescriptor idpSsoDesc) throws MetadataException;

    protected abstract String marshallDescriptor(EntityDescriptor entityDescriptor) throws MetadataException;

    /***
     *  Set the validity period in IDPSSODescriptor loading the value from Federated Authenticator Configuration
     * @param idpSsoDesc IDPSSODescriptor
     * @param samlFederatedAuthenticatorConfig Federated Authenticator Configuration
     * @throws MetadataException
     */
    protected void setValidityPeriod(IDPSSODescriptor idpSsoDesc, FederatedAuthenticatorConfig
            samlFederatedAuthenticatorConfig) throws MetadataException {

        try {
            DateTime currentTime = new DateTime();
            String validiyPeriodStr = getFederatedAuthenticatorConfigProperty(samlFederatedAuthenticatorConfig,
                    IdentityApplicationConstants.Authenticator.SAML2SSO.SAML_METADATA_VALIDITY_PERIOD).getValue();
            if (validiyPeriodStr == null) {
                throw new MetadataException("Setting validity period failed. Null value found.");
            }
            int validityPeriod = Integer.parseInt(validiyPeriodStr);
            DateTime validUntil = new DateTime(currentTime.getMillis() + validityPeriod * ONE_MINUTE_IN_MILLIS);
            idpSsoDesc.setValidUntil(validUntil);
        } catch (NumberFormatException e) {
            throw new MetadataException("Setting validity period failed.", e);
        }
    }

    /***
     *  Enable/disable metadata signing based on SAML Federated Authenticator Configuration
     * @param samlFederatedAuthenticatorConfig SAML Federated Authenticator Configuration
     */
    protected void setSamlMetadataSigningEnabled(FederatedAuthenticatorConfig samlFederatedAuthenticatorConfig) {
        samlMetadataSigningEnabled = Boolean.parseBoolean(getFederatedAuthenticatorConfigProperty(
                samlFederatedAuthenticatorConfig, IdentityApplicationConstants.Authenticator.SAML2SSO.
                        SAML_METADATA_SIGNING_ENABLED).getValue());
    }

    /***
     * Get SAML metadata signing enabled flag
     * @return SAML metadata signing enabled
     */
    protected boolean getSamlMetadataSigningEnabled() {
        return samlMetadataSigningEnabled;
    }

    /***
     *
     * @return Value of wantAUthnRequestSigned flag
     */
    public boolean isWantAuthRequestSigned() {
        return wantAuthRequestSigned;
    }

    /***
     * Set the value of wantAUthnRequestSigned flag
     * @param wantAuthRequestSigned
     */
    public void setWantAuthRequestSigned(boolean wantAuthRequestSigned) {
        this.wantAuthRequestSigned = wantAuthRequestSigned;
    }
}
