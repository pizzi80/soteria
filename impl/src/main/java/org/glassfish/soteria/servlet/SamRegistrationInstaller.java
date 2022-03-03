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

package org.glassfish.soteria.servlet;

import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.Destroyed;
import jakarta.enterprise.context.Initialized;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.spi.CDI;
import jakarta.servlet.ServletContainerInitializer;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;
import org.glassfish.soteria.cdi.CdiExtension;
import org.glassfish.soteria.cdi.spi.CDIPerRequestInitializer;
import org.glassfish.soteria.cdi.spi.impl.LibertyCDIPerRequestInitializer;
import org.glassfish.soteria.mechanisms.jaspic.HttpBridgeServerAuthModule;
import org.glassfish.soteria.mechanisms.jaspic.Jaspic;

import java.util.Set;
import java.util.logging.Logger;

import static java.util.logging.Level.FINEST;
import static java.util.logging.Level.INFO;
import static org.glassfish.soteria.Utils.isEmpty;
import static org.glassfish.soteria.Utils.isNotEmpty;
import static org.glassfish.soteria.mechanisms.jaspic.Jaspic.deregisterServerAuthModule;
import static org.glassfish.soteria.mechanisms.jaspic.Jaspic.registerServerAuthModule;

/**
 * If an HttpAuthenticationMechanism implementation has been found on the classpath, this 
 * initializer installs a bridge SAM that delegates the validateRequest, secureResponse and
 * cleanSubject methods from the SAM to the HttpAuthenticationMechanism.
 * 
 * <p>
 * The bridge SAM uses <code>CDI.current()</code> to obtain the HttpAuthenticationMechanism, therefore
 * fully enabling CDI in the implementation of that interface.
 * 
 * @author Arjan Tijms
 *
 */
//@WebListener
@ApplicationScoped
public class SamRegistrationInstaller { // implements ServletContainerInitializer, ServletContextListener {
    
    private static final Logger logger =  Logger.getLogger(SamRegistrationInstaller.class.getName());

    // CDI 1.1+
    public void onCdiStartup(@Observes @Initialized(ApplicationScoped.class) ServletContext context) {
        // CDI Ready
        logger.info("CDI is ready for Soteria @ ServletContext "+context);

        // Obtain a reference to the CdiExtension that was used to see if
        // there's an enabled bean
        try {
            CDI.current(); //CdiUtils.getBeanManager();

            if (logger.isLoggable(INFO)) {
                String version = getClass().getPackage().getImplementationVersion();
                logger.log(INFO, "Initializing Soteria {0} for context ''{1}''", new Object[]{version, context.getContextPath()});
            }

        } catch (IllegalStateException e) {
            // On GlassFish 4.1.1/Payara 4.1.1.161 CDI is not initialized (org.jboss.weld.Container#initialize is not called),
            // and calling CDI.current() will throw an exception. It's no use to continue then.
            // TODO: Do we need to find out *why* the default module does not have CDI initialized?
            logger.log(FINEST, "CDI not available for app context id: " + Jaspic.getAppContextID(context), e);

            return;
        }

        CdiExtension cdiExtension = CDI.current().select(CdiExtension.class).get(); //CdiUtils.getBeanReference(beanManager, CdiExtension.class);

        if (cdiExtension.isHttpAuthenticationMechanismFound()) {

            // A SAM must be registered at this point, since the programmatically added
            // Listener is for some reason restricted (not allow) from calling
            // getVirtualServerName. At this point we're still allowed to call this.

            // TODO: Ask the Servlet EG to address this? Is there any ground for this restriction???

            CDIPerRequestInitializer cdiPerRequestInitializer = null;

            if (isNotEmpty(System.getProperty("wlp.server.name"))) {
                // Hardcode server check for now. TODO: design/implement proper service loader/SPI for this
                cdiPerRequestInitializer = new LibertyCDIPerRequestInitializer();
                logger.info("Running on Liberty - installing CDI request scope activator");
            }

            registerServerAuthModule(new HttpBridgeServerAuthModule(cdiPerRequestInitializer), context);

            // Add a listener so we can process the context destroyed event, which is needed
            // to de-register the SAM correctly.
            //context.addListener(this);
        }
    }

    public void onCdiShutdown(@Observes @Destroyed(ApplicationScoped.class) ServletContext context) {
        logger.fine("CDI is shutting down for context " + context );
        deregisterServerAuthModule(context);
    }

    // --- ServletContainerInitializer ----------------------------------------------------------------------------

//    @Override
//    public void onStartup(Set<Class<?>> classes, ServletContext context) {
//
//    }


    // --- ServletContextListener ----------------------------------------------------------------------------
    
//    @Override
//    public void contextInitialized(ServletContextEvent event) {
//        // noop
//        logger.fine("contextInitialized");
//    }
//
//    @Override
//    public void contextDestroyed(ServletContextEvent event) {
//        logger.fine("contextDestroyed");
//        deregisterServerAuthModule(event.getServletContext());
//    }
    
}
