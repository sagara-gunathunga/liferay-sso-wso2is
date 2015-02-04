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

package org.wso2.carbon.sso.liferay.persistence.simple;

import org.wso2.carbon.sso.liferay.persistence.SessionPersistence;

import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;

public class SimpleSessionPersistence implements SessionPersistence {

    private Map<String, HttpSession> sessionMap;

    @Override
    public void init() {
        sessionMap = new HashMap<String, HttpSession>();
    }

    @Override
    public void put(String sessionIndex, HttpSession session) {
        sessionMap.put(sessionIndex, session);
    }

    @Override
    public void remove(String sessionIndex) {
        throw new UnsupportedOperationException("Not supported operation");

    }

    @Override
    public void remove(HttpSession session) {
        sessionMap.remove(session);
    }

    @Override
    public HttpSession get(String sessionIndex) {
        return sessionMap.get(sessionIndex);
    }
}
