# Spring Security实现OAuth2/Token设计

## OAuth是什么？

我们经常会碰到这样一个场景：当我们用微信搜索一个新的公众号时，首先需关注该公众号，之后会发现你的微信头像、昵称等信息已经显示在该公众号页面上了。上述过程就是完成了一次OAuth的授权过程。那么，OAuth是什么呢？以下内容摘录于[维基百科](https://zh.wikipedia.org/wiki/开放授权)：

> 开放授权(OAuth)是一个开放标准，允许用户让第三方应用访问该用户在某一网站上存储的私密的资源(如照片，视频，联系人列表)，而无需将用户名和密码提供给第三方应用。
OAuth允许用户提供一个令牌，而不是用户名和密码来访问他们存放在特定服务提供者的数据。每一个令牌授权一个特定的网站(例如，视频编辑网站)在特定的时段(例如，接下来的2小时内)内访问特定的资源(例如仅仅是某一相册中的视频)。这样，OAuth让用户可以授权第三方网站访问他们存储在另外服务提供者的某些特定信息，而非所有内容。

上面场景中：
* 公众号即为第三方应用(也称为client)
* 微信为服务提供商 
* 微信用户为资源所有者(Resource Owner)

这里还有另外2个名词：
* Authorization server(认证服务器)：服务提供商专门用来处理认证的服务器。
* Resource server(资源服务器)：服务提供商存放用户资源的服务器。它与认证服务器可以是同一台服务器，也可以是不同的服务器。

下图是OAuth2的授权流程图：摘录于[RFC 6749](http://www.rfc-base.org/txt/rfc-6749.txt)

     +--------+                               +---------------+
     |        |--(A)- Authorization Request ->|   Resource    |
     |        |                               |     Owner     |
     |        |<-(B)-- Authorization Grant ---|               |
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(C)-- Authorization Grant -->| Authorization |
     | Client |                               |     Server    |
     |        |<-(D)----- Access Token -------|               |
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(E)----- Access Token ------>|    Resource   |
     |        |                               |     Server    |
     |        |<-(F)--- Protected Resource ---|               |
     +--------+                               +---------------+

>   (A)  The client requests authorization from the resource owner.  The
        authorization request can be made directly to the resource owner
        (as shown), or preferably indirectly via the authorization
        server as an intermediary.

>   (B)  The client receives an authorization grant, which is a
        credential representing the resource owner's authorization,
        expressed using one of four grant types defined in this
        specification or using an extension grant type.  The
        authorization grant type depends on the method used by the
        client to request authorization and the types supported by the
        authorization server.

>   (C)  The client requests an access token by authenticating with the
        authorization server and presenting the authorization grant.

>   (D)  The authorization server authenticates the client and validates
        the authorization grant, and if valid, issues an access token.

>   (E)  The client requests the protected resource from the resource
        server and authenticates by presenting the access token.

>   (F)  The resource server validates the access token, and if valid,
        serves the request.

## OAuth2 四种授权方式

* 授权码模式（Authorization Code）
> 授权码模式是流程最严密的授权方式，上述微信授权信息给公众号就是采用的该种方式，其内部流程如下：
>> 首先用户访问某公众号，该公众号将用户导向到微信的认证服务器(也就是关注公众号界面)\
>> 用户同意关注后，认证服务器将用户重新导向公众号事先定义好的Redirection URI，同时附带一个授权码\
>> 公众号收到授权码之后，向认证服务器申请令牌\
>> 认证服务器验证授权码及公众号信息，验证通过后发放访问令牌

* 简化模式（Implicit）
> 与授权码模式相比，少了授权码这个步骤，直接在浏览器中向认证服务申请令牌。该模式不常用。

* 密码模式（Resource Owner Password Credentials）
> 此模式下用户需要将自己的用户名和密码提供给客户端，由客户端带着这些信息向认证服务器申请令牌。通常用在用户完全信任客户端或者客户端与认证服务器是同一套系统下，比如现在流行的微服务架构，每个应用都需要对访问请求进行鉴权，此模式就正好符合该应用场景。下面内容将详细讲解Spring Securiy如何来实现密码模式

* 客户端模式（Client Credentials）
> 该模式是客户端以自己名义向认证服务器申请令牌，与用户无关。该模式严格意义上不属于OAuth授权。

## Spring Security实现密码模式
以下代码是实际项目中的实现，所以会做一些删减，保留最基本的实现，这样也更加容易理解。该实现基于[Spring Boot](http://spring.io/projects/spring-boot)。

首先在项目中加入maven依赖：
```xml
    <dependency>
        <groupId>org.springframework.security.oauth</groupId>
        <artifactId>spring-security-oauth2</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-jwt</artifactId>
    </dependency>
```

接下来我们主要需要完成3件事情
* 配置资源服务器
* 配置认证服务器
* 配置spring security

首先配置资源服务器
```java
@Configuration
@EnableResourceServer
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    @Autowired
    private ResourceServerTokenServices defaultTokenServices;

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        resources.resourceId(resourceId);
        resources.tokenServices(defaultTokenServices);
    }
}
```

```java
@Bean
public TokenStore tokenStore() {
    return new JwtTokenStore(accessTokenConverter());
}

@Bean
public ResourceServerTokenServices defaultTokenServices() {
    final DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
    defaultTokenServices.setTokenEnhancer(accessTokenConverter());//可选项属性，用于添加额外属性到token中
    defaultTokenServices.setTokenStore(tokenStore());
    return defaultTokenServices;
}


@Bean
public JwtAccessTokenConverter accessTokenConverter() {
    JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter() {
        @Override
        public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
            String username = authentication.getUserAuthentication().getName();
            final Map<String, Object> additionalInformation = new HashMap<>();
            additionalInformation.put("username", username);
            ...
            ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInformation);
            return super.enhance(accessToken, authentication);
        }
    };
    accessTokenConverter.setSigningKey(tokenConverterSignKey);
    return accessTokenConverter;
}
```
添加注解`@EnableResourceServer`， 继承`ResourceServerConfigurerAdapter`，重写 `configure(ResourceServerSecurityConfigurer resources)`，其实他是启用了spring security的filter，通过OAuth2的token来认证请求。当然你还需要配置`HttpSecurity`以此来告诉spring security哪些资源需要被保护，可以选择重写`ResourceServerConfigurerAdapter`下的方法，但一般我们会选择重写`WebSecurityConfigurerAdapter`的，因为该类下的order优先级更高。

回到上述代码中，每一个资源服务器需要定义一个Resource Id, 这个Id需和之后的认证服务器中配置的ID相对应。另外需配置一个`ResourceServerTokenServices`,用来实现令牌服务, 该接口提供了`loadAuthentication` 和 `readAccessToken` 方法。我们这里采用了`DefaultTokenServices`这个子类，该类需要设置一个`TokenStore`, 从类名上可以看出这个是一个Token持久化的类，你可以把它理解成一个Repository，该接口有很多现有的实现类，如`InMemoryTokenStore`, `JdbcTokenStore`, `RedisTokenStore`等。本列中我们采用[JWT](https://tools.ietf.org/html/rfc7519)，如果对JWT还不太熟悉的，可以参考一些相关资料，这里不做展开，所以这里我们相应的选取了`JwtTokenStore`，`JwtTokenStore`需要依赖一个`JwtAccessTokenConverter`来进行编码及解码,还需要一个签名公用在资源服务器和授权服务器。到这资源服务器已配置完成。

下面我们来看一下认证服务器

```java
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtAccessTokenConverter accessTokenConverter;

    @Autowired
    private TokenStore tokenStore;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(this.authenticationManager);
        endpoints.accessTokenConverter(accessTokenConverter);
        endpoints.tokenStore(tokenStore);
        endpoints.userDetailsService(userDetailsService);
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient(clientId)
                .authorizedGrantTypes("refresh_token", "password")
                .resourceIds(resourceId)
                .authorities("client")
                .scopes("select")
                .accessTokenValiditySeconds(accessTokenValiditySeconds)//设置access token有效时间
                .refreshTokenValiditySeconds(refreshTokenValiditySeconds)//设置refresh token有效时间
                .secret(clientSecret);
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.allowFormAuthenticationForClients();//允许表单认证
    }
}
```

首先和资源服务器一样，添加`@EnableAuthorizationServer`, 继承`AuthorizationServerConfigurerAdapter`,重写了三个方法。
第一个中关于`AuthenticationManager`，这个由springboot自动配置。`AccessTokenConverter`和`TokenStore`用了和资源服务器配置同样的Bean，`UserDetailsService`我们后来再来讲。
第二个方法主要配置了一个客户端用于password认证，需要注意的是Resource Id需要和资源服务器的一致。

最后我们来看Spring Security部分

```java
@Bean
public UserDetailsService userDetailsService() {
    return username -> {
        if (username == null) {
            throw new UsernameNotFoundException("Username could not be null");
        }
        User user = userRepository.findByUsernameIgnoreCase(username);
        if (user == null) {
            throw new UsernameNotFoundException("User [" + username + "] not exists");
        }
        // create the spring security user
        Set<GrantedAuthority> set = new HashSet<>();
        user.getRoles().forEach(role -> set.add(new SimpleGrantedAuthority("ROLE_" + role.getName())));
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), set);
    };
}
```
```java
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatchers().anyRequest()
                .and()
                .authorizeRequests()
                .antMatchers("/oauth/*").permitAll();
    }
}
```
先看上面提到的`UserDetailsService`，Spring security内部的认证流程比较复杂，`AuthenticationManager`, `AuthenticationProvider`, `UserDetailsService`是三个最重要的顶级接口，其主要流程可以简单概括为在`ClientCredentialsTokenEndpointFilter`中组装信息成`UsernamePasswordAuthenticationToken`，然后由`AuthenticationManager`的实现类，一般是`ProviderManager`,其内部维护了一组`AuthenticationProvider`的实现类，这个才是真正去完成身份认证的，一般的实现类为`DaoAuthenticationProvider`，在该类中用`UserDetailsService`接口的实现类去获取用户数据。理清了这个关系，也就明白了上述代码的含义，我们替换了原本容器中的`UserDetailsService`。当然你也可以替换`AuthenticationManager`，在`SecurityConfiguration`替换其他配置，最后由一个Delegate来完成认证。

配置完成，启动Spring Boot应用后，`TokenEndpoint`会创建一些token服务endpoints。

获取token: 
`
/oauth/token?username={username}&password={password}&grant_type=password&scope=select&client_id={clientId}&client_secret={secret}
`\
之后将获取到的access token放到受保护资源的请求中即可，支持多种方式携带。
可以放Header： 
`
Authentication：Bearer access_token
` \
也可以放request param:
`?access_token={access_token}`\

结语：本文通过关注微信公众号的场景来了解什么OAuth授权，并介绍了四种OAuth2的授权模式。最后通过Spring security + Spring security oauth的代码配置实现了一个简单的密码模式。下篇分享我们可以分析一下spring security oauth2的源码，看看它是如何进行身份验证并颁发令牌，访问保护资源时是如何校验令牌的。

