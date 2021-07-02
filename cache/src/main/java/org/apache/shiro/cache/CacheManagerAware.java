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
package org.apache.shiro.cache;

/**
 * 由使用CacheManager的组件实现的接口，如果CacheManager可用，则希望提供CacheManager。
 * Interface implemented by components that utilize a CacheManager and wish that CacheManager to be supplied if
 * one is available.
 * 这样就可以将使用CacheManager的内部安全组件注入CacheManager，而不必自己创建一个。
 * <p>
 * Shiro内部相应的组件（DefaultSecurityManager）会自动检测相应的对象（如Realm）是否实现了CacheManagerAware并自动注入相应的CacheManager。
 *
 * <p>This is used so internal security components that use a CacheManager can be injected with it instead of having
 * to create one on their own.
 *
 * @since 0.9
 */
public interface CacheManagerAware {

    /**
     * 注入CacheManager
     * 设置有效的CacheManager实例到这个组件中
     * Sets the available CacheManager instance on this component.
     *
     * @param cacheManager the CacheManager instance to set on this component.
     */
    void setCacheManager(CacheManager cacheManager);
}
