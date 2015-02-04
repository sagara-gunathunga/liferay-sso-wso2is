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

package org.wso2.carbon.sso.liferay.action;

import com.liferay.portal.kernel.events.Action;
import com.liferay.portal.kernel.events.ActionException;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.SessionIndex;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.SessionIndexBuilder;
import org.opensaml.xml.io.MarshallingException;
import org.wso2.carbon.sso.liferay.auth.Constants;
import org.wso2.carbon.sso.liferay.auth.Util;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.net.URLEncoder;
import java.util.UUID;

public class SendSAMLLogoutRequestAction extends Action {

    final Log log = LogFactoryUtil.getLog(SendSAMLLogoutRequestAction.class);


    @Override
    public void run(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse)
            throws ActionException {

        LogoutRequest logoutRequest = buildLogoutRequest(httpServletRequest.getSession());
        String relayState = UUID.randomUUID().toString();
        try {
            String encodedReq = URLEncoder.encode(Util.encode(Util.marshall(logoutRequest)));
            String redirectURL = Util.getProperty(Constants.SAML2_SSO_IDENTITY_PROVIDER_URL) + "?SAMLRequest=" + encodedReq + "&RelayState=" + relayState;
            httpServletResponse.sendRedirect(redirectURL);
        } catch (Exception e) {
            throw new ActionException(e);
        }
    }

    private LogoutRequest buildLogoutRequest(HttpSession session) {
        String user = (String) session.getAttribute(Constants.USERNAME);
        String issuerId = (String) session.getAttribute(Constants.ISSUER_ID);
        issuerId = "liferaySP";
        String index = (String) session.getAttribute(Constants.SESSION_INDEX);
        LogoutRequest logoutReq = new LogoutRequestBuilder().buildObject();
        logoutReq.setID(Util.createID());
        logoutReq.setDestination("https://localhost:9443/samlsso");
        DateTime issueInstant = new DateTime();
        logoutReq.setIssueInstant(issueInstant);
        logoutReq.setNotOnOrAfter(new DateTime(issueInstant.getMillis() + 5 * 60 * 1000));
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(issuerId);
        logoutReq.setIssuer(issuer);
        NameID nameId = new NameIDBuilder().buildObject();
        nameId.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
        nameId.setValue(user);
        logoutReq.setNameID(nameId);
        SessionIndex sessionIndex = new SessionIndexBuilder().buildObject();
        sessionIndex.setSessionIndex(index);
        logoutReq.getSessionIndexes().add(sessionIndex);
        logoutReq.setReason("Single Logout");
        if (log.isDebugEnabled()) {
            try {
                log.debug("LogoutRequest " + Util.marshall(logoutReq));
            } catch (MarshallingException e) {
                log.error(e);
            }
        }
        return logoutReq;
    }
}
