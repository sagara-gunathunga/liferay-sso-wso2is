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
import org.wso2.carbon.sso.liferay.auth.Constants;
import org.wso2.carbon.sso.liferay.persistence.SessionPersistenceManager;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class SAMLPostLoginAction extends Action {
    @Override
    public void run(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse)
            throws ActionException {
        String sessionIndex = (String) httpServletRequest.getAttribute(Constants.SESSION_INDEX);
        String userName = (String) httpServletRequest.getAttribute(Constants.USERNAME);
        String issuerId = (String) httpServletRequest.getAttribute(Constants.ISSUER_ID);
        if(sessionIndex != null && userName != null && issuerId != null){
            HttpSession session = httpServletRequest.getSession();
            session.setAttribute(Constants.SESSION_INDEX, sessionIndex);
            session.setAttribute(Constants.USERNAME, userName);
            session.setAttribute(Constants.ISSUER_ID, issuerId);
            SessionPersistenceManager.getSessionpPersistence().put(sessionIndex, session);
        }
    }
}
