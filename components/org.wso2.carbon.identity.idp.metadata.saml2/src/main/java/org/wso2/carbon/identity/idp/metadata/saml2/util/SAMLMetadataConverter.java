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

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.IdentityRegistryResources;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.idp.metadata.saml2.IDPMetadataConstant;
import org.wso2.carbon.identity.idp.metadata.saml2.builder.DefaultIDPMetadataBuilder;
import org.wso2.carbon.identity.idp.metadata.saml2.internal.IDPMetadataSAMLServiceComponentHolder;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderSAMLException;
import org.wso2.carbon.idp.mgt.MetadataException;
import org.wso2.carbon.idp.mgt.util.MetadataConverter;
import org.wso2.carbon.registry.core.Collection;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.registry.core.jdbc.utils.Transaction;
import org.wso2.carbon.registry.core.session.UserRegistry;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

/**
 * This class implements the SAML metadata functionality to convert string to FederatedAuthenticator config
 * and vise versa.
 */
public class SAMLMetadataConverter implements MetadataConverter {

    private static final Log log = LogFactory.getLog(SAMLMetadataConverter.class);

    /**
     * Checks whether this property contains SAML Metadata.
     *
     * @param property The property to be checked for SAML Metadata.
     * @return boolean Whether that property contains SAML Metadata.
     */
    public boolean canHandle(Property property) {

        if (property != null) {
            String meta = property.getName();
            if (meta != null && meta.contains(IDPMetadataConstant.SAML)) {
                return property.getValue() != null && property.getValue().length() > 0;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    /**
     * Retrieves whether the SAML IDP is available in registry or not.
     *
     * @param tenantId ID of the tenant domain.
     * @param idPName  ID of the IDP which is needed to be checked whether it has a metadata string in registry.
     * @return True if the resource exists.
     * @throws IdentityProviderManagementException if there is an error in the registry access.
     */
    public boolean canDelete(int tenantId, String idPName) throws IdentityProviderManagementException {

        try {
            UserRegistry registry = IDPMetadataSAMLServiceComponentHolder.getInstance().getRegistryService()
                    .getGovernanceSystemRegistry(tenantId);
            return registry.resourceExists(IdentityRegistryResources.SAMLIDP + idPName);
        } catch (RegistryException e) {
            throw new IdentityProviderManagementException("Error while checking the registry for the IDP.", e);
        }
    }

    /**
     * Returns a FederatedAuthenticatorConfigObject that is generated using metadata.
     *
     * @param properties Properties required to build the metadata.
     * @param builder    StringBuilder that is used to consume metadata.
     * @return FederatedAuthenticatorConfig containing the required metadata.
     * @throws javax.xml.stream.XMLStreamException If there is an error while converting a string to an OMElement.
     * @throws IdentityProviderManagementException If there is a problem in metadata.
     */
    public FederatedAuthenticatorConfig getFederatedAuthenticatorConfig(Property[] properties, StringBuilder builder)
            throws javax.xml.stream.XMLStreamException, IdentityProviderManagementException {

        String metadata = "";
        final String META_DATA_SAML = "meta_data_saml";
        for (Property property : properties) {

            if (property != null && META_DATA_SAML.equals(property.getName())) {
                metadata = property.getValue();
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
            throw new javax.xml.stream.XMLStreamException("Invalid metadata content, Failed to convert to OMElement",
                    ex);
        }
        FederatedAuthenticatorConfig federatedAuthenticatorConfigMetadata;
        try {
            federatedAuthenticatorConfigMetadata = SAML2SSOFederatedAuthenticatorConfigBuilder.build(element, builder);
        } catch (IdentityApplicationManagementException ex) {
            throw new IdentityProviderManagementException("Invalid file content", ex);
        }

        return federatedAuthenticatorConfigMetadata;
    }

    private Node getIDPSSODescriptor(Document document) {

        if (document.getElementsByTagName("IDPSSODescriptor").item(0) != null) {
            if (document.getElementsByTagName("IDPSSODescriptor").item(0).getNodeType() == Node.ELEMENT_NODE) {
                return document.getElementsByTagName("IDPSSODescriptor").item(0);
            }

        } else if (document.getElementsByTagName("md:IDPSSODescriptor").item(0) != null) {
            if (document.getElementsByTagName("md:IDPSSODescriptor").item(0).getNodeType() == Node.ELEMENT_NODE) {
                return document.getElementsByTagName("md:IDPSSODescriptor").item(0);
            }
        }
        return null;
    }

    private NodeList getKeyDescriptors(Element idpSSODescriptor) {

        if (idpSSODescriptor.getElementsByTagName("KeyDescriptor").item(0) != null) {
            return idpSSODescriptor.getElementsByTagName("KeyDescriptor");
        } else if (idpSSODescriptor.getElementsByTagName("md:KeyDescriptor").item(0) != null) {
            return idpSSODescriptor.getElementsByTagName("md:KeyDescriptor");
        }
        return null;
    }

    private Node getKeyInfoImpl(Element keyDescriptor) {

        if (keyDescriptor.getElementsByTagName("KeyInfo").item(0) != null) {
            return keyDescriptor.getElementsByTagName("KeyInfo").item(0);
        } else if (keyDescriptor.getElementsByTagName("ds:KeyInfo").item(0) != null) {
            return keyDescriptor.getElementsByTagName("ds:KeyInfo").item(0);
        }
        return null;
    }

    private Node getX509Data(Element keyInfo) {

        if (keyInfo.getElementsByTagName("X509Data").item(0) != null) {
            return keyInfo.getElementsByTagName("X509Data").item(0);
        } else if (keyInfo.getElementsByTagName("ds:X509Data").item(0) != null) {
            return keyInfo.getElementsByTagName("ds:X509Data").item(0);
        }
        return null;
    }

    private Node getX509Certificate(Element x509Data) {

        if (x509Data.getElementsByTagName("X509Certificate").item(0) != null) {
            return x509Data.getElementsByTagName("X509Certificate").item(0);
        } else if (x509Data.getElementsByTagName("ds:X509Certificate").item(0) != null) {
            return x509Data.getElementsByTagName("ds:X509Certificate").item(0);
        }
        return null;
    }

    /**
     * If certificate is available, it's converted to PEM format.
     */
    private String configureCertificate(String metadataOriginal) throws IdentityProviderManagementException {

        String metadata;
        DocumentBuilderFactory factory = IdentityUtil.getSecuredDocumentBuilderFactory();
        DocumentBuilder builder;
        Document document;

        try {
            builder = factory.newDocumentBuilder();
            document = builder.parse(new ByteArrayInputStream(metadataOriginal.getBytes()));
            document.getDocumentElement().normalize();

            if (this.getIDPSSODescriptor(document) != null && this.getKeyDescriptors((Element) this.getIDPSSODescriptor
                    (document)) != null) {

                for (int i = 0; i < this.getKeyDescriptors((Element) this.getIDPSSODescriptor(document)).getLength();
                     i++) {

                    if ((this.getKeyDescriptors((Element) this.getIDPSSODescriptor(document)).item(i)).getNodeType() ==
                            Node.ELEMENT_NODE) {

                        if ("signing".equalsIgnoreCase(((Element) (this.getKeyDescriptors((Element) this
                                .getIDPSSODescriptor(document)).item(i))).getAttribute("use"))) {

                            if (this.getKeyInfoImpl((Element) this.getKeyDescriptors((Element) this
                                    .getIDPSSODescriptor(document)).item(i)) != null) {

                                if (this.getX509Data(
                                        (Element) this.getKeyInfoImpl((Element) this.getKeyDescriptors((Element)
                                                this
                                                        .getIDPSSODescriptor(document)).item(i))) != null) {

                                    if (this.getX509Certificate(
                                            (Element) this.getX509Data((Element) this.getKeyInfoImpl(
                                                    (Element) this.getKeyDescriptors((Element)
                                                            this.getIDPSSODescriptor(document)).item(i)))) != null) {

                                        String cert = this.getX509Certificate((Element) this.getX509Data((Element) this
                                                .getKeyInfoImpl((Element) this.getKeyDescriptors((Element)
                                                        this.getIDPSSODescriptor(document)).item(i)))).getTextContent();

                                        if (!(cert.contains("-----BEGIN CERTIFICATE-----") &&
                                                cert.contains("-----END " +
                                                        "CERTIFICATE-----"))) {
                                            cert = "\n-----BEGIN CERTIFICATE-----\n" + cert + "\n-----END " +
                                                    "CERTIFICATE-----\n";
                                        }
                                        this.getX509Certificate(
                                                        (Element) this.getX509Data((Element) this.getKeyInfoImpl(
                                                                (Element) this.getKeyDescriptors((Element)
                                                                        this.getIDPSSODescriptor(document)).item(i))))
                                                .setTextContent(cert);
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

    public String getMetadataString(FederatedAuthenticatorConfig federatedAuthenticatorConfig)
            throws IdentityProviderSAMLException {

        DefaultIDPMetadataBuilder builder = new DefaultIDPMetadataBuilder();
        try {
            if (log.isDebugEnabled()) {
                log.debug("Generating the metadata string.");
            }
            return builder.build(federatedAuthenticatorConfig);
        } catch (MetadataException ex) {
            throw new IdentityProviderSAMLException("Error invoking build in IDPMetadataBuilder", ex);
        }

    }

    public boolean canHandle(FederatedAuthenticatorConfig federatedAuthenticatorConfig) {

        return federatedAuthenticatorConfig != null && federatedAuthenticatorConfig.getName()
                .equals(IdentityApplicationConstants.Authenticator.SAML2SSO.NAME);
    }

    /**
     * Deletes an IDP metadata registry component if it exists.
     *
     * @param tenantId ID of the tenant.
     * @param idPName  Name of the identity provider.
     * @throws IdentityProviderManagementException Error when deleting Identity Provider
     *                                             information from registry.
     */
    public void deleteMetadataString(int tenantId, String idPName) throws IdentityProviderManagementException {

        try {

            UserRegistry registry = IDPMetadataSAMLServiceComponentHolder.getInstance().getRegistryService()
                    .getGovernanceSystemRegistry(tenantId);
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
                        throw new IdentityProviderManagementException(
                                "Error while deleting metadata String in registry for " + idPName, e);
                    }

                }
            } catch (RegistryException e) {
                throw new IdentityProviderManagementException("Error while deleting Identity Provider", e);
            }

        } catch (RegistryException e) {
            throw new IdentityProviderManagementException(
                    "Error while setting a registry object in IdentityProviderManager", e);
        }

    }

    /**
     * Updates an IDP metadata registry component.
     *
     * @param tenantId ID of the tenant.
     * @param idpName  Name of the Identity Provider.
     * @param metadata Metadata in the form of a String.
     * @throws IdentityProviderManagementException Error when deleting Identity Provider
     *                                             information from registry.
     */
    public void saveMetadataString(int tenantId, String idpName, String fedAuthName, String metadata)
            throws IdentityProviderManagementException {

        try {

            UserRegistry registry = IDPMetadataSAMLServiceComponentHolder.getInstance().getRegistryService()
                    .getGovernanceSystemRegistry(tenantId);
            String identityPath = IdentityRegistryResources.IDENTITY;
            String identityProvidersPath = IdentityRegistryResources.IDENTITYPROVIDER;
            String samlIdPPath = IdentityRegistryResources.SAMLIDP + idpName;
            String path = samlIdPPath + "/" + fedAuthName;
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

                    Collection idpCollection = registry.newCollection();
                    registry.put(identityProvidersPath, idpCollection);

                }
                if (!registry.resourceExists(IdentityRegistryResources.SAMLIDP)) {

                    Collection samlIdpCollection = registry.newCollection();
                    registry.put(IdentityRegistryResources.SAMLIDP, samlIdpCollection);

                }
                if (!registry.resourceExists(samlIdPPath)) {
                    Collection samlIdPAuthCollection = registry.newCollection();
                    registry.put(samlIdPPath, samlIdPAuthCollection);
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

                throw new IdentityProviderManagementException("Error while creating resource in registry", e);
            }

        } catch (RegistryException e) {
            throw new IdentityProviderManagementException(
                    "Error while setting a registry object in IdentityProviderManager", e);
        }
    }
}
