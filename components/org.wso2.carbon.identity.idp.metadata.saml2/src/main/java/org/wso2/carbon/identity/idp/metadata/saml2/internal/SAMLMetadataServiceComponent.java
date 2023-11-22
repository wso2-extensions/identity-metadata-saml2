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

package org.wso2.carbon.identity.idp.metadata.saml2.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.http.HttpService;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.idp.metadata.saml2.bean.HttpSAMLMetadataResponseFactory;
import org.wso2.carbon.identity.idp.metadata.saml2.processor.IDPMetadataPublishProcessor;
import org.wso2.carbon.identity.idp.metadata.saml2.util.SAMLMetadataConverter;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.idp.mgt.util.MetadataConverter;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;

/**
 * Identity provider SAML component class.
 */
@Component(
        name = "identity.provider.saml.service.component",
        immediate = true)
public class SAMLMetadataServiceComponent {

    private static final Log log = LogFactory.getLog(SAMLMetadataServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        MetadataConverter converter = new SAMLMetadataConverter();
        context.getBundleContext().registerService(MetadataConverter.class.getName(), converter, null);
        context.getBundleContext().registerService(IdentityProcessor.class.getName(),
                new IDPMetadataPublishProcessor(), null);
        context.getBundleContext().registerService(HttpIdentityResponseFactory.class.getName(),
                new HttpSAMLMetadataResponseFactory(), null);
        if (log.isDebugEnabled()) {
            log.debug("SAML metadata converter is enabled");
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("Identity Management bundle is de-activated");
        }
    }

    @Reference(
            name = "user.realmservice.default",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
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

    @Reference(
            name = "registry.service",
            service = org.wso2.carbon.registry.core.service.RegistryService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRegistryService")
    protected void setRegistryService(RegistryService registryService) {

        IDPMetadataSAMLServiceComponentHolder.getInstance().setRegistryService(registryService);
    }

    protected void unsetRegistryService(RegistryService registryService) {

        if (log.isDebugEnabled()) {
            log.debug("RegistryService unset in IDP Metadata bundle");
        }
        IDPMetadataSAMLServiceComponentHolder.getInstance().setRegistryService(null);
    }

    @Reference(
            name = "config.context.service",
            service = org.wso2.carbon.utils.ConfigurationContextService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetConfigurationContextService")
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

    @Reference(
            name = "osgi.httpservice",
            service = org.osgi.service.http.HttpService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetHttpService")
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

    protected void unsetIdpManager(IdpManager idpManager) {

        IDPMetadataSAMLServiceComponentHolder.getInstance().setIdpManager(null);
    }

    @Reference(
            name = "IdentityProviderManager",
            service = org.wso2.carbon.idp.mgt.IdpManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdpManager")
    protected void setIdpManager(IdpManager idpManager) {

        IDPMetadataSAMLServiceComponentHolder.getInstance().setIdpManager(idpManager);
    }

    @Reference(name = "identity.organization.management.component",
            service = OrganizationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationManager")
    protected void setOrganizationManager(OrganizationManager organizationManager) {

        IDPMetadataSAMLServiceComponentHolder.getInstance().setOrganizationManager(organizationManager);
    }

    protected void unsetOrganizationManager(OrganizationManager organizationManager) {

        IDPMetadataSAMLServiceComponentHolder.getInstance().setOrganizationManager(null);
    }
}

