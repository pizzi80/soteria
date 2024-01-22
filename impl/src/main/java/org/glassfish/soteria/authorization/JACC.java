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

package org.glassfish.soteria.authorization;

import jakarta.security.jacc.PolicyContext;
import jakarta.security.jacc.PolicyContextException;
import jakarta.security.jacc.WebResourcePermission;
import jakarta.security.jacc.WebRoleRefPermission;

import javax.security.auth.Subject;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Set;
import java.util.stream.Collectors;

import static java.security.Policy.getPolicy;

public enum JACC { ;

    public static final String EMPTY = "";
    public static final String SUBJECT_CONTAINER_KEY = "javax.security.auth.Subject.container";
    public static final Principal[] EMPTY_PRINCIPALS = new Principal[0];

    public static Subject getSubject() {
        return getFromContext(SUBJECT_CONTAINER_KEY);
    }

    public static boolean isCallerInRole(String role) {
        
        Subject subject = getSubject();

        return hasPermission( subject , new WebRoleRefPermission(EMPTY,role) );
        
//        EJBContext ejbContext = getEJBContext();
//
//        if (ejbContext != null) {
//
//            // We're called from an EJB
//
//            // To ask for the permission, get the EJB name first.
//            // Unlike the Servlet container there's no automatic mapping
//            // to a global ("") name.
//            String ejbName = getCurrentEJBName(ejbContext);
//            if (ejbName != null) {
//                return hasPermission(subject, new EJBRoleRefPermission(ejbName, role));
//            }
//
//            // EJB name not supported for current container, fallback to going fully through
//            // ejbContext
//            return ejbContext.isCallerInRole(role);
//        }
    }

    public static boolean hasAccessToWebResource(String resource, String... methods) {
        return hasPermission(getSubject(), new WebResourcePermission(resource, methods));
    }

    public static Set<String> getAllDeclaredCallerRoles() {
        // Get the permissions associated with the Subject we obtained
        PermissionCollection permissionCollection = getPermissionCollection(getSubject());

        // Resolve any potentially unresolved role permissions
        permissionCollection.implies(new WebRoleRefPermission(EMPTY, "nothing"));
        //permissionCollection.implies(new EJBRoleRefPermission(EMPTY, "nothing")); // EJB Role ??
        
        // Filter just the roles from all the permissions, which may include things like 
        // java.net.SocketPermission, java.io.FilePermission, and obtain the actual role names.
        return filterRoles(permissionCollection);

    }

    public static boolean hasPermission(Subject subject, Permission permission) {
        return getPolicyPrivileged().implies(fromSubject(subject), permission);
    }

    public static PermissionCollection getPermissionCollection(Subject subject) {
        // This may not be portable. According to the javadoc, "Applications are discouraged from
        // calling this method since this operation may not be supported by all policy implementations.
        // Applications should rely on the implies method to perform policy checks."
        return getPolicyPrivileged().getPermissions(fromSubject(subject));
    }

    private static Policy getPolicyPrivileged() {
        return AccessController.doPrivileged( (PrivilegedAction<Policy>) () -> getPolicy() );
    }

    public static Set<String> filterRoles(PermissionCollection permissionCollection) {

        // Note that the WebRoleRefPermission is given for every Servlet in the application, even when
        // no role refs are used anywhere. This will also include Servlets like the default servlet and the
        // implicit JSP servlet. So if there are 2 application roles, and 3 application servlets, then
        // at least 6 WebRoleRefPermission elements will be present in the collection.
        return  permissionCollection.elementsAsStream()
                                    .filter(JACC::isRolePermission)
                                    .map(Permission::getActions)
                                    .filter(JACC::isCallerInRole)
                                    .collect(Collectors.toSet());
    }

    public static ProtectionDomain fromSubject(Subject subject) {
        return new ProtectionDomain(
                new CodeSource(null, (Certificate[]) null),
                null,
                null,
                subject == null ? EMPTY_PRINCIPALS : subject.getPrincipals().toArray(EMPTY_PRINCIPALS)
        );
    }

    @SuppressWarnings("unchecked")
    public static <T> T getFromContext(String contextName) {
        try {
            //return AccessController.doPrivileged((PrivilegedExceptionAction<T>) () -> (T) PolicyContext.getContext(contextName));
            return (T) PolicyContext.getContext(contextName);
        } catch (PolicyContextException e) {
            throw new RuntimeException(e);
        }
    }
    
    public static boolean isRolePermission(Permission permission) {
        return permission instanceof WebRoleRefPermission; // || permission instanceof EJBRoleRefPermission;
    }

}
