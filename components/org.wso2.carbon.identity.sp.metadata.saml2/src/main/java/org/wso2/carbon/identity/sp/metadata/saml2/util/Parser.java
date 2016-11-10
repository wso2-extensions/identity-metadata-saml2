/*
 * Copyright (c) 2007, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.*;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.parse.BasicParserPool;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.sp.metadata.saml2.Exception.InvalidMetadataException;
import org.wso2.carbon.registry.core.Registry;
import org.xml.sax.SAXException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.opensaml.saml2.metadata.provider.DOMMetadataProvider;

public class Parser {

    private static Log log = LogFactory.getLog(Parser.class);

    protected Registry registry = null;
    public Parser(Registry registry){
        this.registry = registry;
    }

    private void setAssertionConsumerUrl(SPSSODescriptor spssoDescriptor, SAMLSSOServiceProviderDO samlssoServiceProviderDO) throws InvalidMetadataException{
        //Assertion Consumer URL
        //search for the url with the post binding, if there is no post binding select the default url
        List<AssertionConsumerService> assertionConsumerServices = spssoDescriptor.getAssertionConsumerServices();
        if (assertionConsumerServices!=null && assertionConsumerServices.size()>0) {
            List<String> acs = new ArrayList<>();
            boolean foundAssertionConsumerUrl = false;
            for (AssertionConsumerService assertionConsumerService : assertionConsumerServices) {
                acs.add(assertionConsumerService.getLocation());
                if (assertionConsumerService.isDefault()) {
                    samlssoServiceProviderDO.setDefaultAssertionConsumerUrl(assertionConsumerService.getLocation());//changed
                    samlssoServiceProviderDO.setAssertionConsumerUrl(assertionConsumerService.getLocation());//changed
                    foundAssertionConsumerUrl = true;
                }
            }
            samlssoServiceProviderDO.setAssertionConsumerUrls(acs);
            //select atleast one
            if (!foundAssertionConsumerUrl) {
                samlssoServiceProviderDO.setDefaultAssertionConsumerUrl(assertionConsumerServices.get(0).getLocation());
            }
        }else{
            throw new InvalidMetadataException("Invalid metadata content, no Assertion Consumer URL found");
        }
    }
    private void setIssuer(EntityDescriptor entityDescriptor , SAMLSSOServiceProviderDO samlssoServiceProviderDO) throws InvalidMetadataException{
        if(entityDescriptor.getEntityID()==null || entityDescriptor.getEntityID().length()==0){
            throw new InvalidMetadataException("Invalid metadata content, Issuer can't be empty");
        }
        samlssoServiceProviderDO.setIssuer(entityDescriptor.getEntityID());//correct
    }
    private void setNameIDFormat(SPSSODescriptor spssoDescriptor, SAMLSSOServiceProviderDO samlssoServiceProviderDO){
        List<NameIDFormat> nameIDFormats = spssoDescriptor.getNameIDFormats();
        samlssoServiceProviderDO.setNameIDFormat(nameIDFormats.get(0).getFormat());
    }
    private void  setClaims(SPSSODescriptor spssoDescriptor, SAMLSSOServiceProviderDO samlssoServiceProviderDO){
        List<AttributeConsumingService> services = new ArrayList<>();
        services = spssoDescriptor.getAttributeConsumingServices();
        if (services!=null && services.size()>0) {
            //assuming that only one AttrbuteComsumingIndex exists
            AttributeConsumingService service = services.get(0);
            List<RequestedAttribute> attributes = service.getRequestAttributes();
            for (RequestedAttribute attribute : attributes){
                //set the values to claims
            }
        } else {
        }
    }
    private void setDoSignAssertions (SPSSODescriptor spssoDescriptor, SAMLSSOServiceProviderDO samlssoServiceProviderDO){
        samlssoServiceProviderDO.setDoSignAssertions(spssoDescriptor.getWantAssertionsSigned());
    }
    private void  setDoValidateSignatureInRequests(SPSSODescriptor spssoDescriptor, SAMLSSOServiceProviderDO samlssoServiceProviderDO){
        samlssoServiceProviderDO.setDoValidateSignatureInRequests(spssoDescriptor.isAuthnRequestsSigned());
    }
    private void  setSingleLogoutServices(SPSSODescriptor spssoDescriptor, SAMLSSOServiceProviderDO samlssoServiceProviderDO){
        List<SingleLogoutService> singleLogoutServices = spssoDescriptor.getSingleLogoutServices();
        if (singleLogoutServices!=null && singleLogoutServices.size()>0) {
            boolean foundSingleLogoutServicePostBinding = false;
            for (SingleLogoutService singleLogoutService : singleLogoutServices) {
                if (singleLogoutService.getBinding().equals(SAMLConstants.SAML2_POST_BINDING_URI)) {
                    samlssoServiceProviderDO.setSloRequestURL(singleLogoutService.getLocation());
                    samlssoServiceProviderDO.setSloResponseURL(singleLogoutService.getResponseLocation());//changed
                    foundSingleLogoutServicePostBinding = true;
                    break;
                }
            }
            if (!foundSingleLogoutServicePostBinding) {
            }
            samlssoServiceProviderDO.setSloRequestURL(singleLogoutServices.get(0).getLocation());
            samlssoServiceProviderDO.setSloResponseURL(singleLogoutServices.get(0).getResponseLocation());//chnaged
            samlssoServiceProviderDO.setDoSingleLogout(true);
        } else {
            samlssoServiceProviderDO.setDoSingleLogout(false);
        }
    }
    private void  setX509Certificate(EntityDescriptor entityDescriptor,SPSSODescriptor spssoDescriptor, SAMLSSOServiceProviderDO samlssoServiceProviderDO){
        List<KeyDescriptor> descriptors = spssoDescriptor.getKeyDescriptors();
        if (descriptors != null && descriptors.size() > 0) {
            KeyDescriptor descriptor = descriptors.get(0);
            if (descriptor != null) {
                if (descriptor.getUse().toString().equals("SIGNING")) {

                    try {
                        samlssoServiceProviderDO.setX509Certificate(org.opensaml.xml.security.keyinfo.KeyInfoHelper.getCertificates(descriptor.getKeyInfo()).get(0));
                        samlssoServiceProviderDO.setCertAlias(entityDescriptor.getEntityID());
                    } catch (java.security.cert.CertificateException ex) {
                        log.error("Error While setting Certificate and alias", ex);
                    }catch(java.lang.Exception ex){
                        log.error("Error While setting Certificate and alias", ex);
                    }
                }
            }
        }
    }
    private void  setSigningAlgorithmUri(SPSSODescriptor spssoDescriptor, SAMLSSOServiceProviderDO samlssoServiceProviderDO){
        samlssoServiceProviderDO.setSigningAlgorithmUri("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
    }
    private void  setDigestAlgorithmUri(SPSSODescriptor spssoDescriptor, SAMLSSOServiceProviderDO samlssoServiceProviderDO){
        samlssoServiceProviderDO.setDigestAlgorithmUri("http://www.w3.org/2000/09/xmldsig#sha1");
    }

    /**
     * Convert metadata string to samlssoServiceProviderDO object
     *
     * @param metadata ,samlssoServiceProviderDO
     * @return samlssoServiceProviderDO

     */


    public SAMLSSOServiceProviderDO parse(String metadata,SAMLSSOServiceProviderDO samlssoServiceProviderDO) throws InvalidMetadataException{
        EntityDescriptor entityDescriptor = this.generateMetadataObjectFromString(metadata);
        if (entityDescriptor != null) {
            this.setIssuer(entityDescriptor,samlssoServiceProviderDO);
            List<RoleDescriptor> roleDescriptors = entityDescriptor.getRoleDescriptors();
            //TODO: handle when multiple role descriptors are available
            //assuming only one SPSSO is inside the entitydescripter
            RoleDescriptor roleDescriptor = roleDescriptors.get(0);
            SPSSODescriptor spssoDescriptor = (SPSSODescriptor) roleDescriptor;
            this.setAssertionConsumerUrl(spssoDescriptor,samlssoServiceProviderDO);
            //Response Signing Algorithm - not found
            //Response Digest Algorithm - not found
            //NameID format
            this.setNameIDFormat(spssoDescriptor,samlssoServiceProviderDO);
            //Enable Assertion Signing
            this.setDoSignAssertions(spssoDescriptor,samlssoServiceProviderDO);
            //Enable Signature Validation in Authentication Requests and Logout Requests
            this.setDoValidateSignatureInRequests(spssoDescriptor,samlssoServiceProviderDO);
            //Enable Assertion Encryption - not found
            //Enable Single Logout
            this.setSingleLogoutServices(spssoDescriptor,samlssoServiceProviderDO);
            //Enable Attribute Profile - no method found
            //TODO: currently this is stored as a property in registry. need to add it to the metadata file
            // Enable Audience Restriction - not found
            // Enable Recipient Validation - not found
            //Enable IdP Initiated SSO - not found
            // Enable IdP Initiated SLO - not found
           this.setClaims(spssoDescriptor,samlssoServiceProviderDO);
            //setting response signing algorythm - Hardcoded
            //not found in the the spec, no in the SPSSODescriptor
            this.setSigningAlgorithmUri(spssoDescriptor,samlssoServiceProviderDO);
            //setting response digest algorythm - Hardcoded
            //not found in the the spec, no in the SPSSODescriptor
            this.setDigestAlgorithmUri(spssoDescriptor,samlssoServiceProviderDO);
            //set alias and certificate
            this.setX509Certificate(entityDescriptor,spssoDescriptor,samlssoServiceProviderDO);
        }
        return samlssoServiceProviderDO;
    }
    /**
     * Generate metadata object from string
     *
     * @param metadataString
     * @return samlssoServiceProviderDO

     */
    private EntityDescriptor generateMetadataObjectFromString(String metadataString) {
        EntityDescriptor entityDescriptor = null;
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(new ByteArrayInputStream(metadataString.getBytes()));
            Element node = document.getDocumentElement();
            DOMMetadataProvider idpMetaDataProvider = new DOMMetadataProvider(node);
            idpMetaDataProvider.setRequireValidMetadata(true);
            idpMetaDataProvider.setParserPool(new BasicParserPool());
            idpMetaDataProvider.initialize();
            XMLObject xmlObject = idpMetaDataProvider.getMetadata();
            entityDescriptor = (EntityDescriptor) xmlObject;
        } catch (MetadataProviderException | SAXException | ParserConfigurationException | IOException e) {
            log.error("Error While reading Service Provider metadata xml", e);
        }
        return entityDescriptor;
    }
}
