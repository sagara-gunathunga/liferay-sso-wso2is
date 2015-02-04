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

package org.wso2.carbon.sso.liferay.filter;

import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.servlet.filters.BasePortalFilter;
import org.opensaml.saml2.core.AuthnRequest;
import org.wso2.carbon.sso.liferay.auth.AuthReqBuilder;
import org.wso2.carbon.sso.liferay.auth.Constants;
import org.wso2.carbon.sso.liferay.auth.Util;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URLEncoder;
import java.util.UUID;

public class LifeRayAuthFilter extends BasePortalFilter {

    public static Log log = LogFactoryUtil.getLog(LifeRayAuthFilter.class);


    protected void processFilter(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                                 javax.servlet.FilterChain filterChain) throws Exception {
        processSAMLRedirect(httpServletRequest, httpServletResponse);
    }

    private void processSAMLRedirect(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse)
            throws Exception {
        if ((Boolean.TRUE.equals(httpServletRequest.getSession().getAttribute(Constants.AUTHENTICATED))) &&
                        (httpServletRequest.getSession().getAttribute(Constants.USERNAME) != null)) {
            return;
        }

        AuthReqBuilder authReqBuilder = new AuthReqBuilder();
        AuthnRequest authReq = authReqBuilder.buildAuthenticationRequest();

        String encodedReq = URLEncoder.encode(Util.encode(Util.marshall(authReq)));

        String relayState = UUID.randomUUID().toString();

        String redirectURL = Util.getProperty(Constants.SAML2_SSO_IDENTITY_PROVIDER_URL) + "?SAMLRequest=" + encodedReq + "&RelayState=" + relayState;

        httpServletResponse.sendRedirect(redirectURL);
    }


}
