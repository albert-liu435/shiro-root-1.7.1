/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.util;

/**
 * 抽象工厂类
 * TODO - Class JavaDoc
 *
 * @since 1.0
 */
public abstract class AbstractFactory<T> implements Factory<T> {

    private boolean singleton;
    private T singletonInstance;

    public AbstractFactory() {
        this.singleton = true;
    }

    public boolean isSingleton() {
        return singleton;
    }

    public void setSingleton(boolean singleton) {
        this.singleton = singleton;
    }

    /**
     * 返回工厂创建的实例
     *
     * @return
     */
    public T getInstance() {
        T instance;
        //判断是否为单例，默认为单例
        if (isSingleton()) {
            if (this.singletonInstance == null) {
                this.singletonInstance = createInstance();
            }
            instance = this.singletonInstance;
        } else {
            instance = createInstance();
        }
        if (instance == null) {
            String msg = "Factory 'createInstance' implementation returned a null object.";
            throw new IllegalStateException(msg);
        }
        return instance;
    }

    /**
     * 创建单实例
     *
     * @return
     */
    protected abstract T createInstance();
}
