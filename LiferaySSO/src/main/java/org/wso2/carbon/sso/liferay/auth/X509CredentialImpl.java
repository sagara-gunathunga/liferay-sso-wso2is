/*
 * Copyright (c) 2005-2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.sso.liferay.auth;


import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialContextSet;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.x509.X509Credential;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Collection;

public class X509CredentialImpl implements X509Credential {

    private PublicKey publicKey = null;
    private X509Certificate signingCert = null;

    public X509CredentialImpl(BigInteger modulus, BigInteger publicExponent)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, publicExponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        this.publicKey = keyFactory.generatePublic(spec);
    }

    public X509CredentialImpl(X509Certificate cert) {
        this.publicKey = cert.getPublicKey();
        this.signingCert = cert;
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    public X509Certificate getSigningCert() {
        return this.signingCert;
    }

    public X509Certificate getEntityCertificate() {
        return null;
    }

    public Collection<X509CRL> getCRLs() {
        return null;
    }

    public Collection<X509Certificate> getEntityCertificateChain() {
        return null;
    }

    public CredentialContextSet getCredentalContextSet() {
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
        return null;
    }

    public SecretKey getSecretKey() {
        return null;
    }

    public UsageType getUsageType() {
        return null;
    }
}
