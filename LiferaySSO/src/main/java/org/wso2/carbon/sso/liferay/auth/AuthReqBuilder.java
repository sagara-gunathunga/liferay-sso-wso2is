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

import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;

public class AuthReqBuilder {

    public AuthnRequest buildAuthenticationRequest()
            throws Exception {
        Util.doBootstrap();
        AuthnRequest authnRequest = (AuthnRequest) Util.buildXMLObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
        authnRequest.setID(Util.createID());
        authnRequest.setVersion(SAMLVersion.VERSION_20);
        authnRequest.setIssueInstant(new DateTime());
        authnRequest.setIssuer(buildIssuer());
        authnRequest.setNameIDPolicy(buildNameIDPolicy());
        return authnRequest;
    }

    private static Issuer buildIssuer() {
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(Util.getProperty(Constants.SAML2_SSO_ISSUER_ID));
        return issuer;
    }

    private static NameIDPolicy buildNameIDPolicy() {
        NameIDPolicy nameIDPolicy = new NameIDPolicyBuilder().buildObject();
        nameIDPolicy.setFormat(Constants.SAML_2_0_NAMEID_FORMAT_ENTITY);
        nameIDPolicy.setAllowCreate(Boolean.valueOf(true));
        return nameIDPolicy;
    }
}
