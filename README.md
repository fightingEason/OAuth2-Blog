# Spring Security实现OAuth2/Token设计

## OAuth是什么？

现在我们经常会碰到这样一个场景，当我们用微信搜索一个新的公众号，需要确认关注公众号，之后进入公众号之后你会发现你的微信头像及昵称等信息已经显示在了公众号页面上了, 上诉过程就完成了一次OAuth的授权过程。那么OAuth是什么呢？以下内容摘录于[维基百科](https://zh.wikipedia.org/wiki/开放授权)：

> 开放授权(OAuth)是一个开放标准，允许用户让第三方应用访问该用户在某一网站上存储的私密的资源(如照片，视频，联系人列表)，而无需将用户名和密码提供给第三方应用。
OAuth允许用户提供一个令牌，而不是用户名和密码来访问他们存放在特定服务提供者的数据。每一个令牌授权一个特定的网站(例如，视频编辑网站)在特定的时段(例如，接下来的2小时内)内访问特定的资源(例如仅仅是某一相册中的视频)。这样，OAuth让用户可以授权第三方网站访问他们存储在另外服务提供者的某些特定信息，而非所有内容。

上面场景中：
* 公众号即为第三方应用(也称为client)
* 微信为服务提供商 
* 微信用户为资源所有者(Resource Owner)

这里还有另外2个名词：
* Authorization server(认证服务器):服务提供商专门用来处理认证的服务器。
* Resource server(资源服务器):服务提供商存放用户资源的服务器。它与认证服务器，可以是同一台服务器，也可以是不同的服务器。

下图是OAuth2 的授权流程图：

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
> (A)用户打开客户端以后，客户端要求用户给予授权。

> (B)用户同意给予客户端授权。

> (C)客户端使用上一步获得的授权，向认证服务器申请令牌。

> (D)认证服务器对客户端进行认证以后，确认无误，同意发放令牌。

> (E)客户端使用令牌，向资源服务器申请获取资源。

> (F)资源服务器确认令牌无误，同意向客户端开放资源。

   (A)  The client requests authorization from the resource owner.  The
        authorization request can be made directly to the resource owner
        (as shown), or preferably indirectly via the authorization
        server as an intermediary.

   (B)  The client receives an authorization grant, which is a
        credential representing the resource owner's authorization,
        expressed using one of four grant types defined in this
        specification or using an extension grant type.  The
        authorization grant type depends on the method used by the
        client to request authorization and the types supported by the
        authorization server.

   (C)  The client requests an access token by authenticating with the
        authorization server and presenting the authorization grant.

   (D)  The authorization server authenticates the client and validates
        the authorization grant, and if valid, issues an access token.

   (E)  The client requests the protected resource from the resource
        server and authenticates by presenting the access token.

   (F)  The resource server validates the access token, and if valid,
        serves the request.

## OAuth2 四种授权方式

* 授权码模式（Authorization Code）
> 授权码模式是流程最严密的授权方式，上述微信授权信息给公众号就是采用的该种方式，其内部流程如下
>> 首先用户访问某公众号，该公众号将用户导向到微信的认证服务器(也就是关注公众号界面)\
>> 用户同意关注后，认证服务器将用户重新导向公众号事先定义好的Redirection URI,同时附带一个授权码\
>> 公众号收到授权码之后，就向认证服务器申请令牌\
>> 认证服务器验证授权码及公众号信息，验证通过就发放访问令牌

* 简化模式（Implicit）
> 与授权码模式相比，少了授权码这个步骤，直接在浏览器中向认证服务申请令牌。该模式不常用。

* 密码模式（Resource Owner Password Credentials）
> 此模式下用户需要将自己的用户名和密码提供给客户端，然后由客户端带着这些信息向认证服务器申请令牌。通常用在用户完全信任客户端或者客户端与认证服务器是同一套系统下，下面内容详细讲解Spring Securiy如何来实现密码模式

* 客户端模式（Client Credentials）
> 该模式是客户端以自己名义向认证服务器申请令牌，与用户无关，该模式严格意义上不属于OAuth授权。

##Spring Security实现密码模式
TBD.

