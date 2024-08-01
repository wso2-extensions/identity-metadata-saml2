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

package org.wso2.carbon.identity.sp.metadata.saml2.util;

import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.RequestedAttribute;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.saml.common.util.SAMLInitializer;
import org.wso2.carbon.identity.sp.metadata.saml2.exception.InvalidMetadataException;
import org.wso2.carbon.registry.core.Registry;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * This class provides functionality to convert a metadata String to a SAMLSSOServiceProviderDO.
 */
public class Parser {

    private static final Log log = LogFactory.getLog(Parser.class);

    protected Registry registry = null;
    private static final String DEFAULT_NAME_ID_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
    private static boolean isBootStrapped = false;

    public Parser(Registry registry) {

        this.registry = registry;
    }

    private void setAssertionConsumerUrl(SPSSODescriptor spssoDescriptor,
                                         SAMLSSOServiceProviderDO samlssoServiceProviderDO)
            throws InvalidMetadataException {

        // Assertion Consumer URL.
        // Search for the url with post binding, if there is no post binding selected in the default URL.
        List<AssertionConsumerService> assertionConsumerServices = spssoDescriptor.getAssertionConsumerServices();
        if (assertionConsumerServices != null && assertionConsumerServices.size() > 0) {
            List<String> acs = new ArrayList<>();
            boolean foundAssertionConsumerUrl = false;
            for (AssertionConsumerService assertionConsumerService : assertionConsumerServices) {
                if (!acs.contains(assertionConsumerService.getLocation())) {
                    acs.add(assertionConsumerService.getLocation());
                    if (assertionConsumerService.isDefault()) {
                        samlssoServiceProviderDO.setDefaultAssertionConsumerUrl(assertionConsumerService.getLocation());
                        samlssoServiceProviderDO.setAssertionConsumerUrl(assertionConsumerService.getLocation());
                        foundAssertionConsumerUrl = true;
                    }
                }
            }
            samlssoServiceProviderDO.setAssertionConsumerUrls(acs);
            // Select at least one.
            if (!foundAssertionConsumerUrl) {
                samlssoServiceProviderDO.setDefaultAssertionConsumerUrl(assertionConsumerServices.get(0).getLocation());
            }
        } else {
            throw new InvalidMetadataException("Invalid metadata content, no Assertion Consumer URL found.");
        }
    }

    private void setIssuer(EntityDescriptor entityDescriptor, SAMLSSOServiceProviderDO samlssoServiceProviderDO)
            throws InvalidMetadataException {

        if (entityDescriptor.getEntityID() == null || entityDescriptor.getEntityID().length() == 0) {
            throw new InvalidMetadataException("Invalid metadata content, Issuer can't be empty");
        }
        samlssoServiceProviderDO.setIssuer(entityDescriptor.getEntityID());
    }

    private void setNameIDFormat(SPSSODescriptor spssoDescriptor, SAMLSSOServiceProviderDO samlssoServiceProviderDO) {

        List<NameIDFormat> nameIDFormats = spssoDescriptor.getNameIDFormats();
        if (nameIDFormats.isEmpty()) {
            samlssoServiceProviderDO.setNameIDFormat(DEFAULT_NAME_ID_FORMAT);
        } else {
            samlssoServiceProviderDO.setNameIDFormat(nameIDFormats.get(0).getFormat());
        }
    }

    private void setClaims(SPSSODescriptor spssoDescriptor, SAMLSSOServiceProviderDO samlssoServiceProviderDO) {

        List<AttributeConsumingService> services;
        services = spssoDescriptor.getAttributeConsumingServices();
        if (services != null && services.size() > 0) {
            // Assuming that only one AttributeConsumingIndex exists.
            AttributeConsumingService service = services.get(0);
            List<RequestedAttribute> attributes = service.getRequestAttributes();
            for (RequestedAttribute attribute : attributes) {
                //set the values to claims
            }
        }
    }

    private void setDoSignAssertions(SPSSODescriptor spssoDescriptor,
                                     SAMLSSOServiceProviderDO samlssoServiceProviderDO) {

        samlssoServiceProviderDO.setDoSignAssertions(spssoDescriptor.getWantAssertionsSigned());
    }

    private void setDoValidateSignatureInRequests(SPSSODescriptor spssoDescriptor,
                                                  SAMLSSOServiceProviderDO samlssoServiceProviderDO) {

        samlssoServiceProviderDO.setDoValidateSignatureInRequests(spssoDescriptor.isAuthnRequestsSigned());
    }

    private void setSingleLogoutServices(SPSSODescriptor spssoDescriptor,
                                         SAMLSSOServiceProviderDO samlssoServiceProviderDO) {

        List<SingleLogoutService> singleLogoutServices = spssoDescriptor.getSingleLogoutServices();
        if (singleLogoutServices != null && singleLogoutServices.size() > 0) {
            boolean foundSingleLogoutServicePostBinding = false;
            for (SingleLogoutService singleLogoutService : singleLogoutServices) {
                if (singleLogoutService.getBinding().equals(SAMLConstants.SAML2_POST_BINDING_URI)) {
                    samlssoServiceProviderDO.setSloRequestURL(singleLogoutService.getLocation());
                    samlssoServiceProviderDO.setSloResponseURL(singleLogoutService.getResponseLocation());
                    foundSingleLogoutServicePostBinding = true;
                    break;
                }
            }
            samlssoServiceProviderDO.setSloRequestURL(singleLogoutServices.get(0).getLocation());
            samlssoServiceProviderDO.setSloResponseURL(singleLogoutServices.get(0).getResponseLocation());
            samlssoServiceProviderDO.setDoSingleLogout(true);
        } else {
            samlssoServiceProviderDO.setDoSingleLogout(false);
        }
    }

    private void setX509Certificate(EntityDescriptor entityDescriptor, SPSSODescriptor spssoDescriptor,
                                    SAMLSSOServiceProviderDO samlssoServiceProviderDO) {

        List<KeyDescriptor> descriptors = spssoDescriptor.getKeyDescriptors();
        if (descriptors != null && descriptors.size() > 0) {
            KeyDescriptor descriptor = descriptors.get(0);
            if (descriptor != null) {
                if (descriptor.getUse().toString().equals("SIGNING")) {

                    try {
                        samlssoServiceProviderDO.setX509Certificate(org.opensaml.xmlsec.keyinfo.KeyInfoSupport.
                                getCertificates(descriptor.getKeyInfo()).get(0));
                        samlssoServiceProviderDO.setCertAlias(entityDescriptor.getEntityID());
                    } catch (Exception ex) {
                        log.error("Error While setting Certificate and alias", ex);
                    }
                }
            }
        }
    }

    private void setSigningAlgorithmUri(SPSSODescriptor spssoDescriptor,
                                        SAMLSSOServiceProviderDO samlssoServiceProviderDO) {

        String signatureAlgorithm;
        if (Boolean.parseBoolean(IdentityUtil.getProperty(IdentityConstants.ServerConfig
                .SAML_METADATA_SP_ENABLE_SHA256_ALGO))) {
            signatureAlgorithm = IdentityApplicationConstants.XML.SignatureAlgorithmURI.RSA_SHA256;
        } else {
            signatureAlgorithm = IdentityApplicationConstants.XML.SignatureAlgorithmURI.RSA_SHA1;
        }
        samlssoServiceProviderDO.setSigningAlgorithmUri(signatureAlgorithm);
    }

    private void setDigestAlgorithmUri(SPSSODescriptor spssoDescriptor,
                                       SAMLSSOServiceProviderDO samlssoServiceProviderDO) {

        String digestAlgorithm;
        if (Boolean.parseBoolean(IdentityUtil.getProperty(IdentityConstants.ServerConfig
                .SAML_METADATA_SP_ENABLE_SHA256_ALGO))) {
            digestAlgorithm = IdentityApplicationConstants.XML.DigestAlgorithmURI.SHA256;
        } else {
            digestAlgorithm = IdentityApplicationConstants.XML.DigestAlgorithmURI.SHA1;
        }
        samlssoServiceProviderDO.setDigestAlgorithmUri(digestAlgorithm);
    }

    private void setAttributeConsumingServiceIndex(SPSSODescriptor spssoDescriptor, SAMLSSOServiceProviderDO
            samlssoServiceProviderDO) {

        List<AttributeConsumingService> attributeConsumingServices = spssoDescriptor.getAttributeConsumingServices();
        if (attributeConsumingServices != null && attributeConsumingServices.size() > 0) {
            for (AttributeConsumingService attributeConsumingService : attributeConsumingServices) {
                if (attributeConsumingService != null) {
                    int index = attributeConsumingService.getIndex();
                    samlssoServiceProviderDO.setAttributeConsumingServiceIndex(index + "");
                    samlssoServiceProviderDO.setEnableAttributesByDefault(true);
                }
            }
        }
    }

    /**
     * Convert metadata string to a SAMLSSOServiceProviderDO object.
     *
     * @param metadata                 String which contains the metadata.
     * @param samlssoServiceProviderDO SAMLSSOServiceProviderDO object which the extracted metadata is populated to.
     * @return SAMLSSOServiceProviderDO object that is populated.
     */
    public SAMLSSOServiceProviderDO parse(String metadata, SAMLSSOServiceProviderDO samlssoServiceProviderDO)
            throws InvalidMetadataException {

        EntityDescriptor entityDescriptor = this.generateMetadataObjectFromString(metadata);
        if (entityDescriptor != null) {
            this.setIssuer(entityDescriptor, samlssoServiceProviderDO);
            List<RoleDescriptor> roleDescriptors = entityDescriptor.getRoleDescriptors();
            // Assuming that only one SPSSODescriptor is inside the EntityDescriptor.
            SPSSODescriptor spssoDescriptor = null;

            if (CollectionUtils.isEmpty(roleDescriptors)) {
                throw new InvalidMetadataException("Role descriptor not found.");
            }
            for (RoleDescriptor roleDescriptor : roleDescriptors) {
                if (roleDescriptor instanceof SPSSODescriptor) {
                    spssoDescriptor = (SPSSODescriptor) roleDescriptor;
                    break;
                }
            }
            if (spssoDescriptor == null) {
                throw new InvalidMetadataException("Invalid role descriptor class found.");
            }

            this.setAssertionConsumerUrl(spssoDescriptor, samlssoServiceProviderDO);
            // Response Signing Algorithm - not found.
            // Response Digest Algorithm - not found.
            // NameID format.
            this.setNameIDFormat(spssoDescriptor, samlssoServiceProviderDO);
            // Enable Assertion Signing.
            this.setDoSignAssertions(spssoDescriptor, samlssoServiceProviderDO);
            // Enable Signature Validation in Authentication Requests and Logout Requests.
            this.setDoValidateSignatureInRequests(spssoDescriptor, samlssoServiceProviderDO);
            // Enable Assertion Encryption - not found.
            // Enable Single Logout.
            this.setSingleLogoutServices(spssoDescriptor, samlssoServiceProviderDO);
            // Enable Attribute Profile - no method found.
            // TODO: currently this is stored as a property in registry. need to add it to the metadata file.
            // Enable Audience Restriction - not found.
            // Enable Recipient Validation - not found.
            // Enable IdP Initiated SSO - not found.
            // Enable IdP Initiated SLO - not found.
            this.setClaims(spssoDescriptor, samlssoServiceProviderDO);
            // Setting response signing algorithm - Hardcoded.
            // Not found in the spec and not in the SPSSODescriptor.
            this.setSigningAlgorithmUri(spssoDescriptor, samlssoServiceProviderDO);
            // Setting response digest algorithm - Hardcoded.
            // Not found in the spec and not in the SPSSODescriptor.
            this.setDigestAlgorithmUri(spssoDescriptor, samlssoServiceProviderDO);
            // Set alias and certificate.
            this.setX509Certificate(entityDescriptor, spssoDescriptor, samlssoServiceProviderDO);
            // Set attribute consuming service index.
            this.setAttributeConsumingServiceIndex(spssoDescriptor, samlssoServiceProviderDO);
        }
        return samlssoServiceProviderDO;
    }

    /**
     * Generate a metadata object from a string.
     *
     * @param metadataString String containing the metadata.
     * @return EntityDescriptor The metadata object.
     */
    private EntityDescriptor generateMetadataObjectFromString(String metadataString) throws InvalidMetadataException {

        EntityDescriptor entityDescriptor;
        InputStream inputStream;
        try {
            doBootstrap();
            inputStream = new ByteArrayInputStream(metadataString.trim().getBytes(StandardCharsets.UTF_8));
            entityDescriptor = (EntityDescriptor) XMLObjectSupport.unmarshallFromInputStream(
                    XMLObjectProviderRegistrySupport.getParserPool(), inputStream);
        } catch (UnmarshallingException | XMLParserException e) {
            throw new InvalidMetadataException("Error reading SAML Service Provider metadata xml.", e);
        }
        return entityDescriptor;
    }

    /**
     * Initializes the OpenSAML library.
     */
    public static void doBootstrap() {

        if (!isBootStrapped) {
            try {
                SAMLInitializer.doBootstrap();
                isBootStrapped = true;
            } catch (InitializationException e) {
                log.error("Error in bootstrapping the OpenSAML3 library", e);
            }

        }
    }
}
