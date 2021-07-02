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
package org.apache.shiro.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;

/**
 * 这个实在不知道怎么翻译合适。通俗一点理解就是realm可以访问安全相关数据，提供统一的数据封装来给上层做数据校验。shiro的建议是每种数据源定义一个realm，比如用户数据存在数据库可以使用JdbcRealm；存在属性配置文件可以使用PropertiesRealm。一般我们使用shiro都使用自定义的realm。
 * 当有多个realm存在的时候，shiro在做用户校验的时候会按照定义的策略来决定认证是否通过，shiro提供的可选策略有一个成功或者所有都成功等。
 * 一个realm对应了一个CredentialsMatcher，用来做用户提交认证信息和realm获取得用户信息做比对，shiro已经提供了常用的比如用户密码和存储的Hash后的密码的对比。
 * <p>
 * 作者：空挡
 * 链接：https://www.jianshu.com/p/0b1131be7ace
 * 来源：简书
 * 著作权归作者所有。商业转载请联系作者获得授权，非商业转载请注明出处。
 * <p>
 * <p>
 * 域，Shiro从从Realm获取安全数据（如用户、角色、权限），就是说SecurityManager要验证用户身份，那么它需要从Realm获取相应的用户进行比较以确定用户身份是否合法；
 * 也需要从Realm得到用户相应的角色/权限进行验证用户是否能进行操作；可以把Realm看成DataSource，即安全数据源。如我们之前的ini配置方式将使用org.apache.shiro.realm.text.IniRealm。
 * <p>
 * 也就是说对于我们而言，最简单的一个Shiro应用：
 * <p>
 * 1、应用代码通过Subject来进行认证和授权，而Subject又委托给SecurityManager；
 * <p>
 * 2、我们需要给Shiro的SecurityManager注入Realm，从而让SecurityManager能得到合法的用户及其权限进行判断。
 * <p>
 * <p>
 * <p>
 * 从以上也可以看出，Shiro不提供维护用户/权限，而是通过Realm让开发人员自己注入。
 * <p>
 * <p>
 * 在 Shiro 中存在 Realm 这么个概念， Realm 这个单词翻译为 域，其实是非常难以理解的。
 * 域 是什么鬼？和权限有什么毛关系？ 这个单词Shiro的作者用的非常不好，让人很难理解。
 * 那么 Realm 在 Shiro里到底扮演什么角色呢？
 * 当应用程序向 Shiro 提供了 账号和密码之后， Shiro 就会问 Realm 这个账号密码是否对， 如果对的话，其所对应的用户拥有哪些角色，哪些权限。
 * 所以Realm 是什么？ 其实就是个中介。 Realm 得到了 Shiro 给的用户和密码后，有可能去找 ini 文件，就像Shiro 入门中的 shiro.ini，也可以去找数据库，就如同本知识点中的 DAO 查询信息。
 * <p>
 * Realm 就是干这个用的，它才是真正进行用户认证和授权的关键地方。
 * A <tt>Realm</tt> is a security component that can access application-specific security entities
 * such as users, roles, and permissions to determine authentication and authorization operations.
 *
 * <p><tt>Realm</tt>s usually have a 1-to-1 correspondence with a datasource such as a relational database,
 * file system, or other similar resource.  As such, implementations of this interface use datasource-specific APIs to
 * determine authorization data (roles, permissions, etc), such as JDBC, File IO, Hibernate or JPA, or any other
 * Data Access API.  They are essentially security-specific
 * <a href="http://en.wikipedia.org/wiki/Data_Access_Object" target="_blank">DAO</a>s.
 *
 * <p>Because most of these datasources usually contain Subject (a.k.a. User) information such as usernames and
 * passwords, a Realm can act as a pluggable authentication module in a
 * <a href="http://en.wikipedia.org/wiki/Pluggable_Authentication_Modules">PAM</a> configuration.  This allows a Realm to
 * perform <i>both</i> authentication and authorization duties for a single datasource, which caters to the large
 * majority of applications.  If for some reason you don't want your Realm implementation to perform authentication
 * duties, you should override the {@link #supports(org.apache.shiro.authc.AuthenticationToken)} method to always
 * return <tt>false</tt>.
 *
 * <p>Because every application is different, security data such as users and roles can be
 * represented in any number of ways.  Shiro tries to maintain a non-intrusive development philosophy whenever
 * possible - it does not require you to implement or extend any <tt>User</tt>, <tt>Group</tt> or <tt>Role</tt>
 * interfaces or classes.
 *
 * <p>Instead, Shiro allows applications to implement this interface to access environment-specific datasources
 * and data model objects.  The implementation can then be plugged in to the application's Shiro configuration.
 * This modular technique abstracts away any environment/modeling details and allows Shiro to be deployed in
 * practically any application environment.
 *
 * <p>Most users will not implement the <tt>Realm</tt> interface directly, but will extend one of the subclasses,
 * {@link org.apache.shiro.realm.AuthenticatingRealm AuthenticatingRealm} or {@link org.apache.shiro.realm.AuthorizingRealm}, greatly reducing the effort requird
 * to implement a <tt>Realm</tt> from scratch.</p>
 *
 * @see org.apache.shiro.realm.CachingRealm CachingRealm
 * @see org.apache.shiro.realm.AuthenticatingRealm AuthenticatingRealm
 * @see org.apache.shiro.realm.AuthorizingRealm AuthorizingRealm
 * @see org.apache.shiro.authc.pam.ModularRealmAuthenticator ModularRealmAuthenticator
 * @since 0.1
 */
public interface Realm {

    /**
     * 返回一个唯一的Realm名字
     * Returns the (application-unique) name assigned to this <code>Realm</code>. All realms configured for a single
     * application must have a unique name.
     *
     * @return the (application-unique) name assigned to this <code>Realm</code>.
     */
    String getName();

    /**
     * 判断此Realm是否支持此Token
     * Returns <tt>true</tt> if this realm wishes to authenticate the Subject represented by the given
     * {@link org.apache.shiro.authc.AuthenticationToken AuthenticationToken} instance, <tt>false</tt> otherwise.
     *
     * <p>If this method returns <tt>false</tt>, it will not be called to authenticate the Subject represented by
     * the token - more specifically, a <tt>false</tt> return value means this Realm instance's
     * {@link #getAuthenticationInfo} method will not be invoked for that token.
     *
     * @param token the AuthenticationToken submitted for the authentication attempt
     * @return <tt>true</tt> if this realm can/will authenticate Subjects represented by specified token,
     * <tt>false</tt> otherwise.
     */
    boolean supports(AuthenticationToken token);

    /**
     * 根据Token获取认证信息
     * Returns an account's authentication-specific information for the specified <tt>token</tt>,
     * or <tt>null</tt> if no account could be found based on the <tt>token</tt>.
     *
     * <p>This method effectively represents a login attempt for the corresponding user with the underlying EIS datasource.
     * Most implementations merely just need to lookup and return the account data only (as the method name implies)
     * and let Shiro do the rest, but implementations may of course perform eis specific login operations if so
     * desired.
     *
     * @param token the application-specific representation of an account principal and credentials.
     * @return the authentication information for the account associated with the specified <tt>token</tt>,
     * or <tt>null</tt> if no account could be found.
     * @throws org.apache.shiro.authc.AuthenticationException if there is an error obtaining or constructing an AuthenticationInfo object based on the
     *                                                        specified <tt>token</tt> or implementation-specific login behavior fails.
     */
    AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException;

}
