/*
 * Copyright (c) 2015, 2020 Oracle and/or its affiliates. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0, which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * This Source Code may also be made available under the following Secondary
 * Licenses when the conditions for such availability set forth in the
 * Eclipse Public License v. 2.0 are satisfied: GNU General Public License,
 * version 2 with the GNU Classpath Exception, which is available at
 * https://www.gnu.org/software/classpath/license.html.
 *
 * SPDX-License-Identifier: EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0
 */

package org.glassfish.soteria.cdi;

import static jakarta.interceptor.Interceptor.Priority.PLATFORM_BEFORE;
import static jakarta.security.enterprise.AuthenticationStatus.SUCCESS;
import static java.lang.Boolean.TRUE;
import static org.glassfish.soteria.Utils.isImplementationOf;
import static org.glassfish.soteria.Utils.validateRequestMethod;

import java.io.Serializable;
import java.security.Principal;

import jakarta.annotation.Priority;
import javax.security.auth.callback.Callback;

import jakarta.interceptor.AroundInvoke;
import jakarta.interceptor.Interceptor;
import jakarta.interceptor.InvocationContext;
import jakarta.security.auth.message.callback.CallerPrincipalCallback;
import jakarta.security.enterprise.authentication.mechanism.http.AutoApplySession;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.servlet.http.HttpServletRequest;

@Interceptor
@AutoApplySession
@Priority(PLATFORM_BEFORE + 200)
public class AutoApplySessionInterceptor implements Serializable {

    private static final long serialVersionUID = 1L;

    @AroundInvoke
    public Object intercept(InvocationContext invocationContext) throws Exception {
        
        if (isImplementationOf(invocationContext.getMethod(), validateRequestMethod)) {
            
            HttpMessageContext httpMessageContext = (HttpMessageContext)invocationContext.getParameters()[2];
            
            Principal userPrincipal = getPrincipal(httpMessageContext.getRequest());
            
            if (userPrincipal != null) {
                
                httpMessageContext.getHandler().handle(new Callback[] { 
                    new CallerPrincipalCallback(httpMessageContext.getClientSubject(), userPrincipal) }
                );
                         
                return SUCCESS;
            }
            
            Object outcome = invocationContext.proceed();
            
            if (SUCCESS.equals(outcome)) {
                httpMessageContext.getMessageInfo().getMap().put("jakarta.servlet.http.registerSession", TRUE.toString());
            }
            
            return outcome;
        }
        
        return invocationContext.proceed();
    }

    private Principal getPrincipal(HttpServletRequest request) {
        return request.getUserPrincipal();
    }

}
