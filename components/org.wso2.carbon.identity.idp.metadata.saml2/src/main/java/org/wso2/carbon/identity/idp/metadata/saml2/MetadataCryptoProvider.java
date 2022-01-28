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

package org.wso2.carbon.identity.idp.metadata.saml2;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.w3c.dom.Document;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.idp.metadata.saml2.util.BuilderUtil;
import org.wso2.carbon.idp.mgt.MetadataException;

import java.security.cert.CertificateEncodingException;
import java.util.List;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

/**
 * This class adds key descriptors to RoleDescriptors.
 */
public class MetadataCryptoProvider implements CryptoProvider {

    private X509Credential credential;

    private static final Log log = LogFactory.getLog(MetadataCryptoProvider.class);

    public MetadataCryptoProvider() throws MetadataException {

        if (log.isDebugEnabled()) {
            log.debug("Creating the credential object");
        }
        credential = new SignKeyDataHolder();
    }

    public void signMetadata(EntityDescriptor baseDescriptor) throws MetadataException {

        // Add key descriptors for each element in base descriptor.
        List<RoleDescriptor> roleDescriptors = baseDescriptor.getRoleDescriptors();
        if (roleDescriptors.size() > 0) {
            for (RoleDescriptor roleDesc : roleDescriptors) {
                roleDesc.getKeyDescriptors().add(createKeyDescriptor());
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Key Descriptors set for all the role descriptor types");
        }

        // Set signature namespace to the default value.
        try {
            org.apache.xml.security.utils.ElementProxy.setDefaultPrefix(ConfigElements.XMLSIGNATURE_NS,
                    ConfigElements.DEFAULT_XMLSIGNATURE_NS_PREFIX);
        } catch (XMLSecurityException e) {
            throw new MetadataException("Unable to set default prefix for signature element", e);
        }
        org.apache.xml.security.Init.init();
    }

    /**
     * Creates the KeyInfo from the provided Credential.
     *
     * @throws MetadataException if there is an error while creating SAML objects or encoding the certificate.
     */
    private KeyInfo createKeyInfo() throws MetadataException {

        if (log.isDebugEnabled()) {
            log.debug("Creating the KeyInfo element");
        }
        KeyInfo keyInfo = BuilderUtil.createSAMLObject(ConfigElements.XMLSIGNATURE_NS, "KeyInfo", "");
        X509Data data = BuilderUtil.createSAMLObject(ConfigElements.XMLSIGNATURE_NS, "X509Data", "");
        X509Certificate cert = BuilderUtil.createSAMLObject(ConfigElements.XMLSIGNATURE_NS, "X509Certificate", "");

        String value;
        try {
            value = org.apache.xml.security.utils.Base64.encode(credential.getEntityCertificate().getEncoded());
        } catch (CertificateEncodingException e) {
            throw new MetadataException("Error while encoding the certificate.", e);
        }
        cert.setValue(value);
        data.getX509Certificates().add(cert);
        keyInfo.getX509Datas().add(data);

        if (log.isDebugEnabled()) {
            log.debug("Completed KeyInfo element creation");
        }

        return keyInfo;
    }

    /**
     * Creates the key descriptor element with new key info each time called.
     *
     * @return KeyDescriptor with a new KeyInfo element.
     * @throws MetadataException if there is an error while creating the SAML object or KeyInfo.
     */
    private KeyDescriptor createKeyDescriptor() throws MetadataException {

        if (log.isDebugEnabled()) {
            log.debug("Creating the KeyDescriptor element");
        }
        KeyDescriptor keyDescriptor = BuilderUtil.createSAMLObject(ConfigElements.FED_METADATA_NS, "KeyDescriptor", "");
        keyDescriptor.setUse(UsageType.SIGNING);
        keyDescriptor.setKeyInfo(createKeyInfo());

        return keyDescriptor;
    }

    /**
     * Marshall the provided descriptor element contents to DOM.
     *
     * @param desc The entity descriptor to be marshalled.
     * @return Document after marshalling the SAML object to XML.
     * @throws MetadataException if there is an error while marshalling.
     */
    private Document marshallDescriptor(EntityDescriptor desc) throws MetadataException {

        DocumentBuilderFactory factory = IdentityUtil.getSecuredDocumentBuilderFactory();
        DocumentBuilder builder;
        try {
            builder = factory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new MetadataException("Error while creating the document.", e);
        }

        if (log.isDebugEnabled()) {
            log.debug("Marshalling the metadata element contents");
        }
        Document document = builder.newDocument();
        Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(desc);

        try {
            out.marshall(desc, document);
        } catch (MarshallingException e) {
            throw new MetadataException("Error while marshalling the descriptor.", e);
        }

        if (log.isDebugEnabled()) {
            log.debug("Marshalling completed");
        }
        return document;

    }

    @SuppressWarnings("unchecked")
    public Signature getSignature(EntityDescriptor baseDescriptor) {

        QName qname = Signature.DEFAULT_ELEMENT_NAME;
        XMLObjectBuilder<Signature> builder = (XMLObjectBuilder<Signature>)
                XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(qname);
        Signature signature = builder.buildObject(qname);
        signature.setSigningCredential(credential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        baseDescriptor.setSignature(signature);
        return signature;
    }
}
