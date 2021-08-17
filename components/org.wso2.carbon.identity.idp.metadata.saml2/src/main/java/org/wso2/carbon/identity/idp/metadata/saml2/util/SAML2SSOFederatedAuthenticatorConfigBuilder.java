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

package org.wso2.carbon.identity.idp.metadata.saml2.util;

import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.axiom.om.OMElement;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * This class provides functionality to convert metadata String to federatedAuthenticatedConfig.
 */
public class SAML2SSOFederatedAuthenticatorConfigBuilder {
    private static final Log log = LogFactory.getLog(SAML2SSOFederatedAuthenticatorConfigBuilder.class);
    private static final String SIGNING = "SIGNING";
    private static final String ENCRYPTION = "ENCRYPTION";

    /**
     * Convert metadata String to entityDescriptor.
     *
     * @param metadataString
     * @return EntityDescriptor
     */
    private static EntityDescriptor generateMetadataObjectFromString(String metadataString) throws IdentityApplicationManagementException {
        EntityDescriptor entityDescriptor;
        InputStream inputStream;
        try {
            BuilderUtil.doBootstrap();
            inputStream = new ByteArrayInputStream(metadataString.trim().getBytes(StandardCharsets.UTF_8));
            entityDescriptor = (EntityDescriptor) XMLObjectSupport.unmarshallFromInputStream(
                    XMLObjectProviderRegistrySupport.getParserPool(), inputStream);
        } catch (UnmarshallingException | XMLParserException e) {
            throw new IdentityApplicationManagementException("Error while converting file content to entity descriptor", e);
        }
        return entityDescriptor;
    }

    /**
     * Set the values of SamlSSOFederatedAuthenticationConfig from entitydescriptor.
     *
     * @param entityDescriptor ,federatedAuthenticatorConfig,builder
     * @return FederatedAuthenticatorConfig
     */
    private static FederatedAuthenticatorConfig parse(EntityDescriptor entityDescriptor, FederatedAuthenticatorConfig federatedAuthenticatorConfig, StringBuilder builder) throws IdentityApplicationManagementException {

        if (entityDescriptor != null) {
            List<RoleDescriptor> roleDescriptors = entityDescriptor.getRoleDescriptors();
            // Assuming that only one IDPSSODescriptor is inside the EntityDescriptor.
            if (CollectionUtils.isNotEmpty(roleDescriptors)) {
                IDPSSODescriptor idpssoDescriptor = null;
                for (RoleDescriptor roleDescriptor : roleDescriptors) {
                    if (roleDescriptor instanceof IDPSSODescriptor) {
                        idpssoDescriptor = (IDPSSODescriptor) roleDescriptor;
                        break;
                    }
                }
                if (idpssoDescriptor == null) {
                    throw new IdentityApplicationManagementException(
                            "No IDP Descriptors found, invalid file content."
                    );
                }

                Property[] properties = new Property[24];

                Property property = new Property();
                property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.IDP_ENTITY_ID);
                if (entityDescriptor.getEntityID() != null && entityDescriptor.getEntityID().length() > 0) {
                    property.setValue(entityDescriptor.getEntityID());
                } else {
                    property.setValue("");
                    throw new IdentityApplicationManagementException("No Entity ID found, invalid file content");
                }
                properties[0] = property;

                property = new Property();
                property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.SP_ENTITY_ID);
                property.setValue(""); // Not available in the metadata specification.
                properties[1] = property;

                property = new Property();
                property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.SSO_URL);
                List<SingleSignOnService> singleSignOnServices = idpssoDescriptor.getSingleSignOnServices();
                if (CollectionUtils.isNotEmpty(singleSignOnServices)) {
                    boolean found = false;
                    for (SingleSignOnService singleSignOnService : singleSignOnServices) {
                        if (singleSignOnService != null) {
                            if (singleSignOnService.getLocation() != null) {
                                property.setValue(singleSignOnService.getLocation());
                                found = true;
                                break;
                            }
                        }
                    }
                    if (!found) {
                        property.setValue("");
                        throw new IdentityApplicationManagementException("No SSO URL, invalid file content");
                    }
                } else {
                    property.setValue("");
                    throw new IdentityApplicationManagementException("No SSO URL, invalid file content");
                }
                properties[2] = property;

                property = new Property();
                property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_AUTHN_REQ_SIGNED);
                if (idpssoDescriptor.getWantAuthnRequestsSigned() != null && idpssoDescriptor.getWantAuthnRequestsSigned()) {
                    property.setValue("true");
                } else {
                    property.setValue("false");
                }
                properties[3] = property;

                property = new Property();
                property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_LOGOUT_ENABLED);
                List<SingleLogoutService> singleLogoutServices = idpssoDescriptor.getSingleLogoutServices();
                if (CollectionUtils.isNotEmpty(singleLogoutServices)) {
                    property.setValue("true");
                } else {
                    property.setValue("false");
                }
                properties[4] = property;

                property = new Property();
                property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.LOGOUT_REQ_URL);
                if (CollectionUtils.isNotEmpty(singleLogoutServices)) {
                    boolean foundSingleLogoutServicePostBinding = false;
                    for (SingleLogoutService singleLogoutService : singleLogoutServices) {
                        if (singleLogoutService != null) {
                            if (singleLogoutService.getBinding() != null && singleLogoutService.getBinding().equals(SAMLConstants.SAML2_POST_BINDING_URI) && singleLogoutService.getLocation() != null) {
                                property.setValue(singleLogoutService.getLocation());
                                foundSingleLogoutServicePostBinding = true;
                                break;
                            }
                        }
                    }
                    if (!foundSingleLogoutServicePostBinding) {
                        for (SingleLogoutService singleLogoutService : singleLogoutServices) {
                            if (singleLogoutService != null) {
                                if (singleLogoutService.getBinding() != null && singleLogoutService.getLocation() != null) {
                                    property.setValue(singleLogoutService.getLocation());
                                    foundSingleLogoutServicePostBinding = true;
                                    break;
                                }
                            }
                        }
                    }
                    if (!foundSingleLogoutServicePostBinding) {
                        property.setValue("");
                    }
                } else {
                    property.setValue("");
                }
                properties[5] = property;

                property = new Property();
                property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_LOGOUT_REQ_SIGNED);
                property.setValue(""); // Not found in the metadata spec.
                //Not found in the Metadata Spec
                properties[6] = property;

                property = new Property();
                property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_AUTHN_RESP_SIGNED);
                property.setValue(""); // Not found in the metadata spec.
                properties[7] = property;

                property = new Property();
                property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_USER_ID_IN_CLAIMS);
                property.setValue(""); // Not found in the metadata spec.
                properties[8] = property;

                property = new Property();
                property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_ENABLE_ASSERTION_ENCRYPTION);
                property.setValue(""); // Not found in the metadata spec.
                properties[9] = property;

                property = new Property();
                property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.IS_ENABLE_ASSERTION_SIGNING);
                property.setValue(""); // Not found in the metadata spec.
                properties[10] = property;

                List<KeyDescriptor> descriptors = idpssoDescriptor.getKeyDescriptors();
                if (CollectionUtils.isNotEmpty(descriptors)) {
                    for (KeyDescriptor descriptor : descriptors) {
                        if (descriptor != null) {
                            String use = "";
                            try {
                                use = descriptor.getUse().name();
                            } catch (Exception ex) {
                                log.error("Error !!!!", ex);
                            }
                            if (SIGNING.equals(use)) {
                                properties[10].setValue("true");
                            } else if (ENCRYPTION.equals(use)) {
                                properties[9].setValue("true");
                            }
                        }
                    }
                }

                property = new Property();
                property.setName("commonAuthQueryParams"); //S AML query param in the GUI.
                property.setValue(""); // Not found in the metadata spec.
                properties[11] = property;

                property = new Property();
                property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.REQUEST_METHOD);
                property.setValue(""); // Not found in the metadata spec.
                properties[12] = property;

                property = new Property();
                property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.SIGNATURE_ALGORITHM);
                property.setValue(""); // Not found in the metadata spec.
                properties[13] = property;

                property = new Property();
                property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.DIGEST_ALGORITHM);
                property.setValue(""); // Not found in the metadata spec.
                properties[14] = property;

                property = new Property();
                property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.AUTHENTICATION_CONTEXT_COMPARISON_LEVEL);
                property.setValue(""); // Not found in the metadata spec.
                properties[15] = property;

                property = new Property();
                property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_NAME_ID_POLICY);
                property.setValue(""); // Not found in the metadata spec.
                properties[16] = property;

                property = new Property();
                property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.FORCE_AUTHENTICATION);
                property.setValue(""); // Not found in the metadata spec.
                properties[17] = property;

                property = new Property();
                property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.SIGNATURE_ALGORITHM_POST);
                property.setValue(""); // Not found in the metadata spec.
                properties[18] = property;

                property = new Property();
                property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.AUTHENTICATION_CONTEXT_CLASS);
                property.setValue(""); // Not found in the metadata spec.
                properties[19] = property;

                property = new Property();
                property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.ATTRIBUTE_CONSUMING_SERVICE_INDEX);
                property.setValue(""); // Not found in the metadata spec.
                properties[20] = property;

                property = new Property();
                property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_CERT);
                property.setValue(""); // Not found in the metadata spec.
                properties[21] = property;

                property = new Property();
                property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_AUTHN_CONTEXT);
                property.setValue(""); // Not found in the metadata spec.
                properties[22] = property;

                property = new Property();
                property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_PROTOCOL_BINDING);
                property.setValue(""); // Not found in the metadata spec.
                properties[23] = property;

                federatedAuthenticatorConfig.setProperties(properties);

                // Set certificates.
                if (CollectionUtils.isNotEmpty(descriptors)) {
                    for (KeyDescriptor descriptor : descriptors) {
                        if (descriptor != null) {
                            if (descriptor.getUse() != null && "SIGNING".equals(descriptor.getUse().toString())) {
                                try {
                                    String cert;
                                    if (descriptor.getKeyInfo() != null) {
                                        if (descriptor.getKeyInfo().getX509Datas() != null && descriptor.getKeyInfo().getX509Datas().size() > 0) {
                                            for (int k = 0; k < descriptor.getKeyInfo().getX509Datas().size(); k++) {
                                                if (descriptor.getKeyInfo().getX509Datas().get(k) != null) {
                                                    if (descriptor.getKeyInfo().getX509Datas().get(k).getX509Certificates() != null &&
                                                            descriptor.getKeyInfo().getX509Datas().get(0).getX509Certificates().size() > 0) {
                                                        for (int y = 0; y < descriptor.getKeyInfo().getX509Datas().get(k).getX509Certificates().size(); y++) {
                                                            if (descriptor.getKeyInfo().getX509Datas().get(k).getX509Certificates().get(y) != null) {
                                                                if (descriptor.getKeyInfo().getX509Datas().get(k).getX509Certificates().get(y).
                                                                        getValue() != null && descriptor.getKeyInfo().getX509Datas().get(k).getX509Certificates().
                                                                        get(y).getValue().length() > 0) {

                                                                    cert = descriptor.getKeyInfo().getX509Datas().get(k).getX509Certificates().get(y).
                                                                            getValue();

                                                                    builder.append(org.apache.axiom.om.util.Base64.encode(cert.getBytes()));
                                                                    return federatedAuthenticatorConfig;
                                                                }
                                                            }
                                                        }
                                                    }

                                                }
                                            }
                                        }
                                    }
                                } catch (Exception ex) {
                                    log.error("Error While setting Certificate", ex);
                                    break;
                                }
                            }
                        }
                    }
                }
            } else {
                throw new IdentityApplicationManagementException("No Role Descriptors found, invalid file content");
            }
        }
        return federatedAuthenticatorConfig;
    }

    /**
     * Convert metadata OMElement to FederatedAuthenticatorConfigobject.
     *
     * @param saml2FederatedAuthenticatorConfigOM ,builder
     * @return FederatedAuthenticatorConfig
     */

    public static FederatedAuthenticatorConfig build(OMElement saml2FederatedAuthenticatorConfigOM, StringBuilder builder) throws IdentityApplicationManagementException {

        FederatedAuthenticatorConfig federatedAuthenticatorConfig = new FederatedAuthenticatorConfig();
        EntityDescriptor entityDescriptor = generateMetadataObjectFromString(saml2FederatedAuthenticatorConfigOM.toString());
        if (entityDescriptor != null) {
            federatedAuthenticatorConfig = parse(entityDescriptor, federatedAuthenticatorConfig, builder);
        } else {
            throw new IdentityApplicationManagementException("Error while trying to convert to metadata, Invalid file content");
        }
        return federatedAuthenticatorConfig;
    }
}
