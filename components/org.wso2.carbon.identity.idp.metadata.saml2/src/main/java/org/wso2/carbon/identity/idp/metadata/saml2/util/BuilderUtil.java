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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

//import org.opensaml.DefaultBootstrap;
import org.opensaml.core.config.InitializationService;

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;

//import org.opensaml.xml.ConfigurationException;
import org.opensaml.core.config.InitializationException;

//import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.XMLObjectBuilderFactory;

import org.wso2.carbon.idp.mgt.MetadataException;
import javax.xml.namespace.QName;


/**
 * Provides functionality to create a a SAML object of a given type
* */
public class BuilderUtil {

    private static boolean isBootStrapped = false;
    private static final Log log = LogFactory.getLog(BuilderUtil.class);

    public static void doBootstrap() {
        if (!isBootStrapped) {

            Thread thread = Thread.currentThread();
            ClassLoader loader = thread.getContextClassLoader();
            thread.setContextClassLoader(InitializationService.class.getClassLoader());

            try {
                InitializationService.initialize();

                org.opensaml.saml.config.SAMLConfigurationInitializer initializer_1 = new org.opensaml.saml.config.SAMLConfigurationInitializer();
                initializer_1.init();

                org.opensaml.saml.config.XMLObjectProviderInitializer initializer_2 = new org.opensaml.saml.config.XMLObjectProviderInitializer();
                initializer_2.init();

                org.opensaml.core.xml.config.XMLObjectProviderInitializer initializer_3 = new org.opensaml.core.xml.config.XMLObjectProviderInitializer();
                initializer_3.init();

                org.opensaml.core.xml.config.GlobalParserPoolInitializer initializer_4 = new org.opensaml.core.xml.config.GlobalParserPoolInitializer();
                initializer_4.init();
                isBootStrapped = true;
            } catch (InitializationException e) {
                log.error("Error in bootstrapping the OpenSAML2 library", e);
            } finally {
                thread.setContextClassLoader(loader);
            }

        }
    }

    public static <T> T createSAMLObject(String namespaceURI, String localName, String namespacePrefix)
            throws MetadataException {

        XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

        if (log.isDebugEnabled()) {
            log.debug("Building the SAML Object with namespaceURI: " + namespaceURI + " prefix:" + namespacePrefix);
        }

        QName qName = new QName(namespaceURI, localName, namespacePrefix);
        
        T object = (T) builderFactory.getBuilder(qName).buildObject(qName);

        return object;
    }
    


}
