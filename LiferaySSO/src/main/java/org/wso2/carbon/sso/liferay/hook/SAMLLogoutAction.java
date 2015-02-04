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
import com.liferay.portal.security.auth.AutoLogin;
import com.liferay.portal.security.auth.AutoLoginException;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.SessionIndex;
import org.wso2.carbon.sso.liferay.auth.Util;
import org.wso2.carbon.sso.liferay.persistence.SessionPersistence;
import org.wso2.carbon.sso.liferay.persistence.SessionPersistenceManager;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

public class SAMLLogoutAction implements AutoLogin {

    final Log log = LogFactoryUtil.getLog(SAMLLogoutAction.class);

    @Override
    public String[] login(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse)
            throws AutoLoginException {

        if (httpServletRequest.getParameter("SAMLRequest") != null) {
            try {
                LogoutRequest logoutRequest = getLogoutRequest(httpServletRequest);
                proccesLogoutRequest(logoutRequest);
            } catch (IOException e) {
                log.error("IO error occurred while reading LogoutRequest", e);
            }
        }
        return new String[0];
    }

    private LogoutRequest getLogoutRequest(HttpServletRequest httpServletRequest) throws IOException {
        String logoutRequestStr = Util.decode(httpServletRequest.getParameter("SAMLRequest"));
        LogoutRequest logoutRequest = (LogoutRequest) Util.unmarshall(logoutRequestStr);
        if (log.isDebugEnabled()) {
            log.debug("SAML LogoutRequest is received. : " + logoutRequestStr);
        }
        return logoutRequest;
    }

    private void  proccesLogoutRequest(LogoutRequest logoutRequest) {
        SessionPersistence sessionPersistence = SessionPersistenceManager.getSessionpPersistence();
            for( SessionIndex index : logoutRequest.getSessionIndexes()){
                HttpSession session = sessionPersistence.get(index.getSessionIndex());
                if(session != null){
                    session.invalidate();
                    sessionPersistence.remove(session);
                    log.info("SAML LogoutRequest executed successful");
                    break;
                }
            }
    }
}
