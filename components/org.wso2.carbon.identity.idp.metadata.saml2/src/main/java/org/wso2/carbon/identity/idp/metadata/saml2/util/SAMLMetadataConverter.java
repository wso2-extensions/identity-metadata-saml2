/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.idp.metadata.saml2.util;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.idp.metadata.saml2.IDPMetadataConstant;
import org.wso2.carbon.identity.idp.metadata.saml2.builder.DefaultIDPMetadataBuilder;
import org.wso2.carbon.identity.idp.metadata.saml2.internal.IDPMetadataSAMLServiceComponentHolder;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.AXIOMUtil;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.IdentityRegistryResources;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderSAMLException;
import org.wso2.carbon.idp.mgt.MetadataException;
import org.wso2.carbon.idp.mgt.util.MetadataConverter;
import org.wso2.carbon.registry.core.Collection;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.registry.core.jdbc.utils.Transaction;
import org.wso2.carbon.registry.core.session.UserRegistry;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;

/**
 * This class implements the SAML metadata functionality to convert string to FederatedAuthenticator config nad vise versa
 */
public class SAMLMetadataConverter implements MetadataConverter {

    /**
     * Retrieves whether this property contains SAML Metadata     *
     *
     * @param property
     * @return boolean     *
     */
    public boolean canHandle(Property property) {
        if (property != null) {
            String meta = property.getName();
            if (meta != null && meta.contains(IDPMetadataConstant.SAML)) {
                if (property.getValue() != null && property.getValue().length() > 0) {
                    return true;
                }
                return false;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }


    /**
     * Returns a FederatuedAuthenticatorConfigObject that is generated using metadata
     *
     * @param properties,builder
     * @return FederatedAuthenticatorConfig
     * @throws javax.xml.stream.XMLStreamException, IdentityProviderManagementException
     */
    public FederatedAuthenticatorConfig getFederatedAuthenticatorConfig(Property properties[], StringBuilder builder) throws javax.xml.stream.XMLStreamException, IdentityProviderManagementException {


        String metadata = "";
        for (int y = 0; y < properties.length; y++) {

            if (properties[y] != null && properties[y].getName() != null && properties[y].getName().toString().equals("meta_data_saml")) {
                metadata = properties[y].getValue();
            }
        }

        if (metadata.equals("")) {
            throw new IdentityProviderManagementException("No metadata found");
        } else {
            metadata = configureCertificate(metadata);
        }

        OMElement element;
        try {
            element = AXIOMUtil.stringToOM(metadata);
        } catch (javax.xml.stream.XMLStreamException ex) {
            throw new javax.xml.stream.XMLStreamException("Invalid metadata content, Failed to convert to OMElement");
        }
        FederatedAuthenticatorConfig federatedAuthenticatorConfigMetadata;
        try {
            federatedAuthenticatorConfigMetadata = SAML2SSOFederatedAuthenticatorConfigBuilder.build(element, builder);
        } catch (IdentityApplicationManagementException ex) {
            throw new IdentityProviderManagementException("Invalid file content");
        }

        return federatedAuthenticatorConfigMetadata;
    }

    /**
     * If certificate is available, it's converted to PEM format
     */
    private String configureCertificate(String metadataOriginal) throws IdentityProviderManagementException {

        String metadata = "";
        DocumentBuilderFactory factory = IdentityUtil.getSecuredDocumentBuilderFactory();
        DocumentBuilder builder;
        Document document;

        try {
            builder = factory.newDocumentBuilder();
            document = builder.parse(new ByteArrayInputStream(metadataOriginal.getBytes()));
            document.getDocumentElement().normalize();

            if (document.getElementsByTagName("IDPSSODescriptor").item(0).getNodeType() == Node.ELEMENT_NODE) {

                for (int i = 0; i < ((Element) document.getElementsByTagName("IDPSSODescriptor").item(0))
                        .getElementsByTagName("KeyDescriptor").getLength(); i++) {

                    if ((((Element) document.getElementsByTagName("IDPSSODescriptor").item(0))
                            .getElementsByTagName("KeyDescriptor").item(i)).getNodeType() == Node.ELEMENT_NODE) {

                        if ("signing".equalsIgnoreCase(((Element) (((Element) document.
                                getElementsByTagName("IDPSSODescriptor").item(0))
                                .getElementsByTagName("KeyDescriptor").item(i))).getAttribute("use"))) {

                            if ((((Element) (((Element) document.getElementsByTagName("IDPSSODescriptor").
                                    item(0))
                                    .getElementsByTagName("KeyDescriptor").item(i))).getElementsByTagName("KeyInfo").item(0)).
                                    getNodeType() == Node.ELEMENT_NODE) {

                                if ((((Element) (((Element) (((Element) document.getElementsByTagName("IDPSSODescriptor")
                                        .item(0))
                                        .getElementsByTagName("KeyDescriptor").item(i))).getElementsByTagName("KeyInfo").
                                        item(0))).getElementsByTagName("X509Data").item(0)).getNodeType() == Node.ELEMENT_NODE) {

                                    if ((((Element) (((Element) (((Element) (((Element) document.getElementsByTagName
                                            ("IDPSSODescriptor")
                                            .item(0))
                                            .getElementsByTagName("KeyDescriptor").item(i))).getElementsByTagName("KeyInfo").
                                            item(0))).getElementsByTagName("X509Data").item(0))).
                                            getElementsByTagName("X509Certificate").item(0)).getNodeType() == Node.ELEMENT_NODE) {

                                        String cert = ((Element) (((Element) (((Element) (((Element) (((Element) document.getElementsByTagName
                                                ("IDPSSODescriptor")
                                                .item(0))
                                                .getElementsByTagName("KeyDescriptor").item(i))).getElementsByTagName("KeyInfo").
                                                item(0))).getElementsByTagName("X509Data").item(0))).
                                                getElementsByTagName("X509Certificate").item(0))).getTextContent();

                                        if (!(cert.contains("-----BEGIN CERTIFICATE-----") && cert.contains("-----END " +
                                                "CERTIFICATE-----"))) {
                                            cert = "\n-----BEGIN CERTIFICATE-----\n" + cert + "\n-----END " +
                                                    "CERTIFICATE-----\n";
                                        }

                                        ((Element) (((Element) (((Element) (((Element) (((Element) document.getElementsByTagName
                                                ("IDPSSODescriptor")
                                                .item(0))
                                                .getElementsByTagName("KeyDescriptor").item(i))).getElementsByTagName("KeyInfo").
                                                item(0))).getElementsByTagName("X509Data").item(0))).
                                                getElementsByTagName("X509Certificate").item(0))).setTextContent(cert);

                                    }
                                }
                            }
                        }
                    }
                }
            }

            Transformer transformer;
            StreamResult streamResult;
            StringWriter stringWriter = new StringWriter();
            transformer = TransformerFactory.newInstance().newTransformer();
            streamResult = new StreamResult(stringWriter);
            DOMSource source = new DOMSource(document);
            transformer.transform(source, streamResult);
            stringWriter.close();
            metadata = stringWriter.toString();

        } catch (Exception ex) {
            throw new IdentityProviderManagementException("Error Configuring certificate", ex);
        }
        return metadata;
    }

    public String getMetadataString(FederatedAuthenticatorConfig federatedAuthenticatorConfig) throws IdentityProviderSAMLException {

        DefaultIDPMetadataBuilder builder = new DefaultIDPMetadataBuilder();
        try {

            String metadata = builder.build(federatedAuthenticatorConfig);
            return metadata;
        } catch (MetadataException ex) {
            throw new IdentityProviderSAMLException("Error invoking build in IDPMetadataBuilder", ex);
        }

    }

    public boolean canHandle(FederatedAuthenticatorConfig federatedAuthenticatorConfig) {
        if (federatedAuthenticatorConfig != null && federatedAuthenticatorConfig.getName()
                .equals(IdentityApplicationConstants.Authenticator.SAML2SSO.NAME)) {
            return true;
        }
        return false;
    }

    /**
     * Deletes an IDP metadata registry component if exists
     *
     * @param idPName , tennantId
     * @throws IdentityProviderManagementException Error when deleting Identity Provider
     *                                             information from registry
     */
    public void deleteMetadataString(int tenantId, String idPName) throws IdentityProviderManagementException {
        try {

            UserRegistry registry = IDPMetadataSAMLServiceComponentHolder.getInstance().getRegistryService().getGovernanceSystemRegistry(tenantId);
            String samlIdpPath = IdentityRegistryResources.SAMLIDP;
            String path = samlIdpPath + idPName;

            try {

                if (registry.resourceExists(path)) {
                    boolean isTransactionStarted = Transaction.isStarted();
                    try {

                        if (!isTransactionStarted) {
                            registry.beginTransaction();
                        }

                        registry.delete(path);

                        if (!isTransactionStarted) {
                            registry.commitTransaction();
                        }

                    } catch (RegistryException e) {
                        if (!isTransactionStarted) {
                            registry.rollbackTransaction();
                        }
                        throw new IdentityProviderManagementException("Error while deleting metadata String in registry for " + idPName);
                    }


                }
            } catch (RegistryException e) {
                throw new IdentityProviderManagementException("Error while deleting Identity Provider", e);
            }


        } catch (RegistryException e) {
            throw new IdentityProviderManagementException("Error while setting a registry object in IdentityProviderManager");
        }

    }

    /**
     * Updates an IDP metadata registry component
     *
     * @param idpName , tennantId, metadata
     * @throws IdentityProviderManagementException Error when deleting Identity Provider
     *                                             information from registry
     */
    public void saveMetadataString(int tenantId, String idpName, String metadata) throws IdentityProviderManagementException {

        try {

            UserRegistry registry = IDPMetadataSAMLServiceComponentHolder.getInstance().getRegistryService().getGovernanceSystemRegistry(tenantId);
            String identityPath = IdentityRegistryResources.IDENTITY;
            String identityProvidersPath = IdentityRegistryResources.IDENTITYPROVIDER;
            String samlIdpPath = IdentityRegistryResources.SAMLIDP;
            String path = samlIdpPath + idpName;
            Resource resource;
            resource = registry.newResource();
            resource.setContent(metadata);


            boolean isTransactionStarted = Transaction.isStarted();
            if (!isTransactionStarted) {
                registry.beginTransaction();
            }

            try {
                if (!registry.resourceExists(identityPath)) {

                    Collection idpCollection = registry.newCollection();
                    registry.put(identityPath, idpCollection);

                }
                if (!registry.resourceExists(identityProvidersPath)) {

                    org.wso2.carbon.registry.core.Collection idpCollection = registry.newCollection();
                    registry.put(identityProvidersPath, idpCollection);

                }
                if (!registry.resourceExists(samlIdpPath)) {

                    org.wso2.carbon.registry.core.Collection samlIdpCollection = registry.newCollection();
                    registry.put(samlIdpPath, samlIdpCollection);

                }
                if (!registry.resourceExists(path)) {
                    registry.put(path, resource);
                } else {
                    registry.delete(path);
                    registry.put(path, resource);
                }

                if (!isTransactionStarted) {
                    registry.commitTransaction();
                }
            } catch (RegistryException e) {

                if (!isTransactionStarted) {
                    registry.rollbackTransaction();
                }

                throw new IdentityProviderManagementException("Error while creating resource in registry");
            }

        } catch (RegistryException e) {
            throw new IdentityProviderManagementException("Error while setting a registry object in IdentityProviderManager");
        }
    }


}
