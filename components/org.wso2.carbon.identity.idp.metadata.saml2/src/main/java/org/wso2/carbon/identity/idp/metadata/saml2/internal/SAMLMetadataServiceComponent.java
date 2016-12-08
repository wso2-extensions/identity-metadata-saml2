/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.idp.metadata.saml2.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.http.HttpService;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.idp.metadata.saml2.bean.HttpSAMLMetadataResponseFactory;
import org.wso2.carbon.identity.idp.metadata.saml2.processor.IDPMetadataPublishProcessor;
import org.wso2.carbon.idp.mgt.IdpManagerService;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;

/**
 * @scr.component name="identity.provider.saml.service.component" immediate="true"
 * @scr.reference name="registry.service"
 * interface="org.wso2.carbon.registry.core.service.RegistryService"
 * cardinality="1..1" policy="dynamic" bind="setRegistryService"
 * unbind="unsetRegistryService"
 * @scr.reference name="user.realmservice.default" interface="org.wso2.carbon.user.core.service.RealmService"
 * cardinality="1..1" policy="dynamic" bind="setRealmService"
 * unbind="unsetRealmService"
 * @scr.reference name="config.context.service"
 * interface="org.wso2.carbon.utils.ConfigurationContextService" cardinality="1..1"
 * policy="dynamic" bind="setConfigurationContextService"
 * unbind="unsetConfigurationContextService"
 * @scr.reference name="osgi.httpservice" interface="org.osgi.service.http.HttpService"
 * cardinality="1..1" policy="dynamic" bind="setHttpService"
 * unbind="unsetHttpService"
 * @scr.reference name="IdentityProviderManager"
 * interface="org.wso2.carbon.idp.mgt.IdpManagerService" cardinality="1..1"
 * policy="dynamic" bind="setIdpManager" unbind="unsetIdpManager"
 */

public class SAMLMetadataServiceComponent {

    private static Log log = LogFactory.getLog(SAMLMetadataServiceComponent.class);


    protected void activate(ComponentContext context) {

        context.getBundleContext().registerService(IdentityProcessor.class.getName(), new IDPMetadataPublishProcessor
                (), null);
        context.getBundleContext().registerService(HttpIdentityResponseFactory.class.getName(), new
                HttpSAMLMetadataResponseFactory(), null);
        if (log.isDebugEnabled()) {
            log.debug("SAML metadata converter is enabled");
        }
    }

    protected void deactivate(ComponentContext context) {
        if (log.isDebugEnabled()) {
            log.debug("Identity Management bundle is de-activated");
        }
    }

    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("RealmService is set in IDP Metadata bundle");
        }
        IDPMetadataSAMLServiceComponentHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Realm Service is set in the IDP Metadata bundle");
        }
        IDPMetadataSAMLServiceComponentHolder.getInstance().setRealmService(null);
    }


    public static void setRegistryService(RegistryService registryService) {
        IDPMetadataSAMLServiceComponentHolder.getInstance().setRegistryService(registryService);
    }


    protected void unsetRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("RegistryService unset in IDP Metadata bundle");
        }
        IDPMetadataSAMLServiceComponentHolder.getInstance().setRegistryService(null);
    }

    protected void setConfigurationContextService(ConfigurationContextService configCtxService) {
        if (log.isDebugEnabled()) {
            log.debug("Configuration Context Service is set in the SAML SSO bundle");
        }
        IDPMetadataSAMLServiceComponentHolder.getInstance().setConfigCtxService(configCtxService);
    }

    protected void unsetConfigurationContextService(ConfigurationContextService configCtxService) {
        if (log.isDebugEnabled()) {
            log.debug("Configuration Context Service is unset in the SAML SSO bundle");
        }
        IDPMetadataSAMLServiceComponentHolder.getInstance().setConfigCtxService(null);
    }

    protected void setHttpService(HttpService httpService) {
        if (log.isDebugEnabled()) {
            log.debug("HTTP Service is set in the SAML SSO bundle");
        }
        IDPMetadataSAMLServiceComponentHolder.getInstance().setHttpService(httpService);
    }

    protected void unsetHttpService(HttpService httpService) {
        if (log.isDebugEnabled()) {
            log.debug("HTTP Service is unset in the SAML SSO bundle");
        }
        IDPMetadataSAMLServiceComponentHolder.getInstance().setHttpService(null);
    }

    protected void unsetIdpManager(IdpManagerService idpManager) {
        IDPMetadataSAMLServiceComponentHolder.getInstance().setIdpManager(null);
    }

    protected void setIdpManager(IdpManagerService idpManager) {
        IDPMetadataSAMLServiceComponentHolder.getInstance().setIdpManager(idpManager);
    }


}
