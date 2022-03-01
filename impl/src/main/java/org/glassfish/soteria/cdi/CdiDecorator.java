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

import jakarta.enterprise.context.spi.CreationalContext;
import jakarta.enterprise.inject.spi.*;

import java.lang.annotation.Annotation;
import java.lang.reflect.Member;
import java.lang.reflect.Type;
import java.util.Set;
import java.util.function.BiFunction;

// WIP - Builder for dynamic decorators. May not be needed and/or replaced by
// CDI 2.0 bean builder
// See http://weld.cdi-spec.org/news/2015/02/25/weld-300Alpha5/#_bean_builder_api
public class CdiDecorator<T> extends CdiProducer<T> implements Decorator<T> {
    
    private Class<T> decorator;
    private Type delegateType;
    private Set<Type> decoratedTypes;
    
    private BeanManager beanManager;
    private InjectionPoint decoratorInjectionPoint;
    private Set<InjectionPoint> injectionPoints;
    
    private BiFunction<CreationalContext<T>, Object, T> create;
    
    
    @Override
    public T create(CreationalContext<T> creationalContext) {
        return create.apply(creationalContext, beanManager.getInjectableReference(decoratorInjectionPoint, creationalContext));
    }
    
    @Override
    public Set<InjectionPoint> getInjectionPoints() {
        return injectionPoints;
    }

    public Type getDelegateType() {
        return delegateType;
    }
 
    public Set<Type> getDecoratedTypes() {
        return decoratedTypes;
    }
    
    public Set<Annotation> getDelegateQualifiers() {
        return Set.of();
    }
    
    public CdiDecorator<T> decorator(Class<T> decorator) {
        this.decorator = decorator;
        beanClassAndType(decorator);
        return this;
    }
    
    public CdiDecorator<T> delegateAndDecoratedType(Type type) {
        delegateType = type;
        decoratedTypes = Set.of(type);
        return this;
    }
    
    public CdiProducer<T> create(BeanManager beanManager, BiFunction<CreationalContext<T>, Object, T> create) {
        
        decoratorInjectionPoint = new DecoratorInjectionPoint(
                getDelegateType(), 
                beanManager.createAnnotatedType(decorator).getFields().iterator().next(), 
                this);
            
            injectionPoints = Set.of(decoratorInjectionPoint);
            
            this.beanManager = beanManager;
        
        this.create = create;
        return this;
    }
    
    private static class DecoratorInjectionPoint implements InjectionPoint {
        
        private final Set<Annotation> qualifiers = Set.of(new DefaultAnnotationLiteral());
        
        private final Type type; 
        private final AnnotatedField<?> annotatedField; 
        private final Bean<?> bean;

        public DecoratorInjectionPoint(Type type, AnnotatedField<?> annotatedField, Bean<?> bean) {
            this.type = type;
            this.annotatedField = annotatedField;
            this.bean = bean;
        }
        
        public Type getType() {
            return type;
        }
        
        public Set<Annotation> getQualifiers() {
            return qualifiers;
        }
        
        public Bean<?> getBean() {
            return bean;
        }
        
        public Member getMember() {
            return annotatedField.getJavaMember();
        }
        
        public Annotated getAnnotated() {
            return annotatedField;
        }
        
        public boolean isDelegate() {
            return true;
        }

        public boolean isTransient() {
            return false;
        }
      
    }

}
