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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialContextSet;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.X509Credential;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.keystore.KeyStoreAdmin;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.idp.mgt.MetadataException;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import javax.crypto.SecretKey;

/**
 * This class holds key configurations.
 */
public class SignKeyDataHolder implements X509Credential {

    public static final String SECURITY_SAML_SIGN_KEY_STORE_LOCATION = "Security.SAMLSignKeyStore.Location";
    public static final String SECURITY_SAML_SIGN_KEY_STORE_TYPE = "Security.SAMLSignKeyStore.Type";
    public static final String SECURITY_SAML_SIGN_KEY_STORE_PASSWORD = "Security.SAMLSignKeyStore.Password";
    public static final String SECURITY_SAML_SIGN_KEY_STORE_KEY_ALIAS = "Security.SAMLSignKeyStore.KeyAlias";
    public static final String SECURITY_SAML_SIGN_KEY_STORE_KEY_PASSWORD = "Security.SAMLSignKeyStore.KeyPassword";

    private String signatureAlgorithm = null;

    private X509Certificate[] issuerCerts = null;

    private PrivateKey issuerPrivateKey = null;
    private static KeyStore superTenantSignKeyStore = null;

    private static final Log log = LogFactory.getLog(SignKeyDataHolder.class);

    /**
     * Represent OpenSAML compatible certificate credential.
     */
    public SignKeyDataHolder() throws MetadataException {

        int tenantID;
        String userTenantDomain;

        try {
            userTenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            tenantID = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();

            if (log.isDebugEnabled()) {
                log.debug("Key store used for signing is based on the tenant:  " + userTenantDomain);
            }

            if (tenantID != MultitenantConstants.SUPER_TENANT_ID) {
                initializeKeyDataForTenant(tenantID, userTenantDomain);
            } else {
                if (isSignKeyStoreConfigured()) {
                    initializeKeyDataForSuperTenantFromSignKeyStore();
                } else {
                    initializeKeyDataForSuperTenantFromSystemKeyStore();
                }
            }

        } catch (Exception e) {
            throw new MetadataException("Error occurred while creating certificate credentials", e);
        }

    }

    /**
     * Set parameters needed for build Sign Key from the tenant KeyStore.
     *
     * @param tenantID     ID of the tenant.
     * @param tenantDomain Domain of the tenant.
     * @throws Exception if there is an error while retrieving from the key store manager.
     */
    private void initializeKeyDataForTenant(int tenantID, String tenantDomain) throws Exception {

        if (log.isDebugEnabled()) {
            log.debug("Initializing Key Data for tenant: " + tenantDomain);
        }

        String keyStoreName = tenantDomain.trim().replace(".", "-") + ".jks";
        String keyAlias = tenantDomain;
        KeyStoreManager keyMan = KeyStoreManager.getInstance(tenantID);

        KeyStore keyStore = keyMan.getKeyStore(keyStoreName);
        issuerPrivateKey = (PrivateKey) keyMan.getPrivateKey(keyStoreName, tenantDomain);

        Certificate[] certificates = keyStore.getCertificateChain(keyAlias);
        issuerCerts = Arrays.copyOf(certificates, certificates.length, X509Certificate[].class);

        signatureAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256;
        String pubKeyAlgo = issuerCerts[0].getPublicKey().getAlgorithm();
        if ("DSA".equalsIgnoreCase(pubKeyAlgo)) {
            signatureAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_DSA;
        }
    }

    /**
     * Set parameters needed for build Sign Key from the Sign KeyStore which is defined under Security.KeyStore in
     * carbon.xml.
     *
     * @throws Exception if the keyAlias is empty or if there is an error while retrieving through the key store admin.
     */
    private void initializeKeyDataForSuperTenantFromSystemKeyStore() throws Exception {

        if (log.isDebugEnabled()) {
            log.debug("Initializing Key Data for super tenant using system key store");
        }

        String keyAlias = ServerConfiguration.getInstance().getFirstProperty("Security.KeyStore.KeyAlias");
        if (StringUtils.isBlank(keyAlias)) {
            throw new MetadataException("Invalid file configurations. The key alias is not found.");
        }

        KeyStoreAdmin keyAdmin = new KeyStoreAdmin(MultitenantConstants.SUPER_TENANT_ID);
        KeyStoreManager keyMan = KeyStoreManager.getInstance(MultitenantConstants.SUPER_TENANT_ID);
        issuerPrivateKey = (PrivateKey) keyAdmin.getPrivateKey(keyAlias, true);

        Certificate[] certificates = keyMan.getPrimaryKeyStore().getCertificateChain(keyAlias);
        issuerCerts = Arrays.copyOf(certificates, certificates.length, X509Certificate[].class);

        signatureAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256;
        String pubKeyAlgo = issuerCerts[0].getPublicKey().getAlgorithm();
        if ("DSA".equalsIgnoreCase(pubKeyAlgo)) {
            signatureAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_DSA;
        }
    }

    /**
     * Check whether separate configurations for sign KeyStore available.
     *
     * @return true if necessary configurations are defined for sign KeyStore; false otherwise.
     */
    private boolean isSignKeyStoreConfigured() {

        String keyStoreLocation = ServerConfiguration.getInstance().getFirstProperty(
                SECURITY_SAML_SIGN_KEY_STORE_LOCATION);
        String keyStoreType = ServerConfiguration.getInstance().getFirstProperty(
                SECURITY_SAML_SIGN_KEY_STORE_TYPE);
        String keyStorePassword = ServerConfiguration.getInstance().getFirstProperty(
                SECURITY_SAML_SIGN_KEY_STORE_PASSWORD);
        String keyAlias = ServerConfiguration.getInstance().getFirstProperty(
                SECURITY_SAML_SIGN_KEY_STORE_KEY_ALIAS);
        String keyPassword = ServerConfiguration.getInstance().getFirstProperty(
                SECURITY_SAML_SIGN_KEY_STORE_KEY_PASSWORD);

        return StringUtils.isNotBlank(keyStoreLocation) && StringUtils.isNotBlank(keyStoreType)
                && StringUtils.isNotBlank(keyStorePassword) && StringUtils.isNotBlank(keyAlias)
                && StringUtils.isNotBlank(keyPassword);
    }

    /**
     * Set parameters needed for build Sign Key from the Sign KeyStore which is defined under Security.SAMLSignKeyStore
     * in carbon.xml.
     *
     * @throws MetadataException if there is an error while using the key store and certificates.
     */
    private void initializeKeyDataForSuperTenantFromSignKeyStore() throws MetadataException {

        if (log.isDebugEnabled()) {
            log.debug("Initializing Key Data for super tenant using separate sign key store");
        }

        try {
            if (superTenantSignKeyStore == null) {

                String keyStoreLocation = ServerConfiguration.getInstance().getFirstProperty(
                        SECURITY_SAML_SIGN_KEY_STORE_LOCATION);
                try (FileInputStream is = new FileInputStream(keyStoreLocation)) {
                    String keyStoreType = ServerConfiguration.getInstance().getFirstProperty(
                            SECURITY_SAML_SIGN_KEY_STORE_TYPE);
                    KeyStore keyStore = KeyStore.getInstance(keyStoreType);

                    char[] keyStorePassword = ServerConfiguration.getInstance().getFirstProperty(
                            SECURITY_SAML_SIGN_KEY_STORE_PASSWORD).toCharArray();
                    keyStore.load(is, keyStorePassword);

                    superTenantSignKeyStore = keyStore;

                } catch (FileNotFoundException e) {
                    throw new MetadataException("Unable to locate keystore", e);
                } catch (IOException e) {
                    throw new MetadataException("Unable to read keystore", e);
                } catch (CertificateException e) {
                    throw new MetadataException("Unable to read certificate", e);
                }
            }

            String keyAlias = ServerConfiguration.getInstance().getFirstProperty(
                    SECURITY_SAML_SIGN_KEY_STORE_KEY_ALIAS);
            char[] keyPassword = ServerConfiguration.getInstance().getFirstProperty(
                    SECURITY_SAML_SIGN_KEY_STORE_KEY_PASSWORD).toCharArray();
            Key key = superTenantSignKeyStore.getKey(keyAlias, keyPassword);

            if (key instanceof PrivateKey) {
                issuerPrivateKey = (PrivateKey) key;

                Certificate[] certificates = superTenantSignKeyStore.getCertificateChain(keyAlias);
                issuerCerts = Arrays.copyOf(certificates, certificates.length, X509Certificate[].class);

                signatureAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA;
                Certificate cert = superTenantSignKeyStore.getCertificate(keyAlias);
                PublicKey publicKey = cert.getPublicKey();
                String pubKeyAlgo = publicKey.getAlgorithm();
                if ("DSA".equalsIgnoreCase(pubKeyAlgo)) {
                    signatureAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_DSA;
                }
            } else {
                throw new MetadataException("Configured signing KeyStore private key is invalid");
            }

        } catch (NoSuchAlgorithmException e) {
            throw new MetadataException("Unable to load algorithm", e);
        } catch (UnrecoverableKeyException e) {
            throw new MetadataException("Unable to load key", e);
        } catch (KeyStoreException e) {
            throw new MetadataException("Unable to load keystore", e);
        }
    }

    public Collection<X509CRL> getCRLs() {

        return null;
    }

    public X509Certificate getEntityCertificate() {

        return issuerCerts[0];
    }

    public Collection<X509Certificate> getEntityCertificateChain() {

        return Arrays.asList(issuerCerts);
    }

    /**
     * Get the credential context set.
     *
     * @return This method is not supported so, the return is null.
     */
    public CredentialContextSet getCredentialContextSet() {

        return null;
    }

    public Class<? extends Credential> getCredentialType() {

        return null;
    }

    public String getEntityId() {

        return null;
    }

    public Collection<String> getKeyNames() {

        return null;
    }

    public PrivateKey getPrivateKey() {

        return issuerPrivateKey;
    }

    public PublicKey getPublicKey() {

        return issuerCerts[0].getPublicKey();
    }

    public SecretKey getSecretKey() {

        return null;
    }

    public UsageType getUsageType() {

        return null;
    }
}
