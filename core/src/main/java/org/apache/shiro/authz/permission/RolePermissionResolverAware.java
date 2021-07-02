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
package org.apache.shiro.authz.permission;

/**
 * 由组件实现的接口，该组件希望使用任何配置的<tt>RolePermissionResolver</tt>应用程序，这些应用程序可能已经存在，而不是可能自己创建一个。
 * Interface implemented by a component that wishes to use any application-configured <tt>RolePermissionResolver</tt> that
 * might already exist instead of potentially creating one itself.
 *
 * <p>This is mostly implemented by {@link org.apache.shiro.authz.Authorizer Authorizer} and
 * {@link org.apache.shiro.realm.Realm Realm} implementations since they
 * are the ones performing permission checks and need to know how to resolve Strings into
 * {@link org.apache.shiro.authz.Permission Permission} instances.
 *
 * @since 1.0
 */
public interface RolePermissionResolverAware {

    /**
     * 设置解析字符串为权限集合的解析器
     * Sets the specified <tt>RolePermissionResolver</tt> on this instance.
     *
     * @param rpr the <tt>RolePermissionResolver</tt> being set.
     */
    public void setRolePermissionResolver(RolePermissionResolver rpr);
}
