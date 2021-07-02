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
package org.apache.shiro.config;

/**
 * 由可由资源位置（路径）配置的组件实现的接口。
 * Interface implemented by components that can be configured by resource locations (paths).
 *
 * @since 1.2
 */
public interface ResourceConfigurable {

    /**
     * 方便方法，该方法接受以逗号分隔的配置位置（资源路径）字符串。
     * Convenience method that accepts a comma-delimited string of config locations (resource paths).
     *
     * @param locations comma-delimited list of config locations (resource paths).
     */
    void setConfigLocations(String locations);

    /**
     * 设置将用于配置实例的配置位置（资源路径）。
     * Sets the configuration locations (resource paths) that will be used to configure the instance.
     *
     * @param locations the configuration locations (resource paths) that will be used to configure the instance.
     */
    void setConfigLocations(String[] locations);

}