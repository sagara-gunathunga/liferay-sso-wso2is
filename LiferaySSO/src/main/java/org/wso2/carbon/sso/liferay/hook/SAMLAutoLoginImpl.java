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

package org.wso2.carbon.sso.liferay.hook;

import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.model.User;
import com.liferay.portal.security.auth.AutoLogin;
import com.liferay.portal.security.auth.AutoLoginException;
import com.liferay.portal.service.UserLocalServiceUtil;
import com.liferay.portal.util.PortalUtil;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Statement;
import org.opensaml.saml2.core.Subject;
import org.opensaml.xml.XMLObject;
import org.wso2.carbon.sso.liferay.auth.Constants;
import org.wso2.carbon.sso.liferay.auth.Util;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

public class SAMLAutoLoginImpl implements AutoLogin {

    final Log log = LogFactoryUtil.getLog(SAMLAutoLoginImpl.class);

    public String[] login(HttpServletRequest request, HttpServletResponse httpServletResponse)
            throws AutoLoginException {
        String[] credentials = null;

        if (Boolean.TRUE.equals(request.getSession().getAttribute(Constants.AUTHENTICATED))) {
            String username = (String) request.getSession().getAttribute(Constants.USERNAME);
            credentials = populateCredentialArray(request, username);
            if (log.isDebugEnabled()) {
                log.debug("User : " + username + " is successfully authenticated.");
            }

        } else if (request.getParameter(Constants.SAML_RESPONSE) != null) {
            try {
                String responseStr = Util.decode(request.getParameter(Constants.SAML_RESPONSE));
                XMLObject responseXmlObject =  Util.unmarshall(responseStr);

                //Before proceed make sure this a SAML Response.
                if(!(responseXmlObject instanceof Response)){
                     //SAML LogoutResponse also come here.
                     return credentials;
                }
                Response samlResponse = (Response)responseXmlObject;
                if (log.isDebugEnabled()) {
                    log.debug("SAML Response is received. : " + responseStr);
                }

                if (Util.validateSignature(samlResponse)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Signature validation is successful for assertion : " + samlResponse.getID());
                    }

                    List assertions = samlResponse.getAssertions();
                    if ((assertions != null) && (assertions.size() > 0)) {
                        String username = getUserName((Assertion) assertions.get(0));
                        String sessionIndex = getSessionIndex((Assertion) assertions.get(0));
                        String issuerId = samlResponse.getIssuer().getValue();
                        if (username != null & sessionIndex != null) {
                            credentials = populateCredentialArray(request, username);
                            storeSessionData(request, username, sessionIndex, issuerId);
                            if (log.isDebugEnabled()) {
                                log.debug("User : " + username + " is successfully authenticated.");
                            }
                        }
                    }
                } else {
                    log.warn("Signature validation is failed for the SAML Response : " + samlResponse.getID());
                }
            } catch (Exception e) {
                log.error("Error when processing the SAML Response.", e);
            }
        }
        return credentials;
    }

    private String getUserName(Assertion assertion) {
        Subject subject = assertion.getSubject();
        if ((subject != null) &&
            (subject.getNameID() != null)) {
            return subject.getNameID().getValue();
        }
        return null;
    }

    private String getSessionIndex(Assertion assertion) {
        for (Statement statement : assertion.getStatements()) {
            if (statement instanceof AuthnStatement) {
                return ((AuthnStatement) statement).getSessionIndex();
            }
        }
        return null;
    }

    private void storeSessionData(HttpServletRequest request, String username, String sessionIndex, String issuerId) {
        request.setAttribute(Constants.AUTHENTICATED, "true");
        request.setAttribute(Constants.USERNAME, username);
        request.setAttribute(Constants.SESSION_INDEX, sessionIndex);
        request.setAttribute(Constants.ISSUER_ID, issuerId);
    }

    private String[] populateCredentialArray(HttpServletRequest request, String username) {
        String[] credentials = null;
        try {
            long companyId = PortalUtil.getCompanyId(request);
            User user = UserLocalServiceUtil.getUserByScreenName(companyId, username);
            long userId = user.getUserId();
            String password = user.getPassword();

            credentials = new String[3];
            credentials[0] = Long.toString(userId);
            credentials[1] = password;
            credentials[2] = Boolean.TRUE.toString();
        } catch (Exception e) {
            log.error("Error when extracting user information from LifeRay", e);
        }
        return credentials;
    }
}