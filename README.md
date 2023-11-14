# Spring Boot 安全指南



## 1、组件/依赖安全风险防范

### Actuator

#### 风险说明

Spring Boot项目中可引入Actuator对健康状态等进行监控。Actuator提供了多种不同的端点（endpoints），如health、info等。但是部分端点对外暴露后可能会导致信息泄露或远程命令执行（RCE）等风险。

#### 安全实践

##### 非必要不引入Actuator依赖

根据需求评估是否需要引入Actuator，可检查是否存在如下依赖配置

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-actuator</artifactId>
    </dependency>
</dependencies>
```

##### 最小化端点暴露

生产环境中仅使用必须的端点，避免暴露高风险端点。在properties 或yaml 格式的配置文件进行如下配置，仅启用并暴露特定端点(以health、info为例)

```properties
#properties 配置 
#默认禁用所有端点
management.endpoints.enabled-by-default=false
#启用特定端点
management.endpoint.health.enabled=true
#暴露特定端点
management.endpoints.web.exposure.include=health,info

```

```yaml
#yaml 配置
management:
  endpoints:
    enabled-by-default: false
  endpoint:
    info:
      enabled: true
  endpoints:
    web:
      exposure:
        include: "health,info"
```

##### 使用spring security 保护 Actuator



#### 参考链接

https://docs.spring.io/spring-boot/docs/3.2.x/reference/html/actuator.html

https://cloud.tencent.com/developer/article/1816814

### Alibaba Druid

#### 风险说明

Spring Boot项目中可引入 Alibaba Druid，Druid 是一个 JDBC 组件库，包含数据库连接池、SQL Parser 等组件, 被大量业务和技术产品使用或集成。如果未对对Duird 监控页面进行合理配置，攻击者能够未授权访问session监控功能，获取合法用户会话，进而登录业务系统造成数据窃取或系统破坏。

#### 安全实践

##### 为Druid监控页面配置账号密码

web.xml文件中，进行如下配置：

```xml
<!-- 配置 Druid 监控信息显示页面 -->  
<servlet>  
    <servlet-name>DruidStatView</servlet-name>  
    <servlet-class>com.alibaba.druid.support.http.StatViewServlet</servlet-class>  
    <init-param>  
	<!-- 允许清空统计数据 -->  
	<param-name>resetEnable</param-name>  
	<param-value>true</param-value>  
    </init-param>  
    <init-param>  
	<!-- 用户名 -->  
	<param-name>loginUsername</param-name>  
	<param-value>自定义用户名</param-value>  
    </init-param>  
    <init-param>  
	<!-- 密码 -->  
	<param-name>loginPassword</param-name>  
	<param-value>自定义密码</param-value>  
    </init-param>  
</servlet>  
<servlet-mapping>  
    <servlet-name>DruidStatView</servlet-name>  
    <url-pattern>/druid/*</url-pattern>  
</servlet-mapping>  
```

##### 对Druid监控页面访问源地址进行限制

web.xml文件中，进行如下配置：

```xml
 <servlet>
      <servlet-name>DruidStatView</servlet-name>
      <servlet-class>com.alibaba.druid.support.http.StatViewServlet</servlet-class>
  	<init-param>
  		<param-name>allow</param-name>
  		<param-value>允许访问的源地址</param-value>
  	</init-param>
  	<init-param>
  		<param-name>deny</param-name>
  		<param-value>拒绝访问的源地址</param-value>
  	</init-param>
  </servlet>
```

- **注意！！！ 如果allow没有配置或者为空，则允许所有访问**
- deny优先于allow，如果在deny列表中，就算在allow列表中，也会被拒绝。

#### 参考链接

https://github.com/alibaba/druid/wiki/%E9%85%8D%E7%BD%AE_StatViewServlet%E9%85%8D%E7%BD%AE

## 2 API安全风险防范

### 2.1 失效的对象级授权

#### 风险说明

攻击者可以通过操纵在请求中发送的对象的ID来利用容易受到破坏的对象级授权攻击的API端点。对象ID可以是从连续整数、UUID或泛型字符串中的任何内容。例如api端点： /shops/{shopName}/revenue_data，攻击者替换shopname的值，如果权限校验不当，可能越权访问其他商户信息。

#### 安全实践

##### 实现依赖于用户策略和层级的适当授权机制

参考如下拦截器实现

```java
@Component
public class AuthorizeInterceptor implements HandlerInterceptor {

    private static final String USER_KEY = "APP_USER_ID";

    @Autowired
    UserService userService;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if(!(handler instanceof HandlerMethod)){
            return true;
        }
        final String userId = request.getHeader(USER_KEY);
        if(canAccess(userId,request.getRequestURI())){
            return true;
        }
        //处理鉴权失败
//        final Rsp rsp = Rsp.fail(403, "无权访问");
        Map<String,Object> rsp = new HashMap<>(2);
        rsp.put("code",403);
        rsp.put("msg","无权访问");
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json; charset=utf-8");
        final PrintWriter writer = response.getWriter();
        writer.write(JSON.toJSONString(rsp));
        return false;
    }

    private boolean canAccess(String userId,String path) {
        if(userId == null){
            return false;
        }
        final Set<String> userAccessUrls = userService.getUserAccessUrls(userId);
        return userAccessUrls.contains(path);
    }

}
```

##### 使用随机和不可预测的值作为记录ID的GUID

可考虑生成随机id作为主键，具体实现参考

百度UidGenerator： https://github.com/baidu/uid-generator

美团Leaf： https://github.com/Meituan-Dianping/Leaf

阿里巴巴Seata：https://github.com/seata/seata

##### 编写测试用例以评估授权机制的脆弱性

参考测试用例1：

- get、post参数内是否有userid
  - 无 -- 测试通过无问题
  - 有 -- 执行下一步测试判断是否为假参数

- 请求参数内有当前用户的userid， 删除该参数判断接口返回
  - 接口正常执行（表示此参数为假参数、未使用）-- 测试通过
  - 接口异常（表示后端错误使用userid -- 存在越权

参考测试用例2：

- 资源id替换后，重放请求 （用户1- 动作1-对象id1 替换成 用户1- 动作1-对象id2）
  - 接口运行异常，无法正常完成功能 -- 测试通过
  - 接口运行效果一致 -- 存在越权

#### 参考链接

https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/

https://blog.csdn.net/luostudent/article/details/124119997

https://zhuanlan.zhihu.com/p/413297914

### 2.2 失效的用户身份验证 

#### 风险说明

身份验证机制很容易成为攻击者的目标，因为它对所有人都是公开的。软件和安全工程师对身份验证边界和固有实现复杂性的误解使身份验证问题普遍存在。

API在以下情况下易受攻击：

- 允许攻击者对同一用户帐户执行暴力攻击，而不提供验证码/帐户锁定机制
- 允许弱密码
- 发送敏感的身份验证详细信息，例如URL中携带token和密码
- 允许用户更改其电子邮件地址、当前密码或执行任何其他敏感操作，而无需密码确认
- 不验证令牌的真实性
- 接受未签名/弱签名的JWT令牌（ `{"alg":"none"}` ）
- 不验证JWT到期日期
- 使用纯文本、非加密或弱散列密码
- 使用弱加密密钥

#### 安全实践

##### 不要在身份验证、令牌生成或密码存储方面重复造轮子。使用业界标准组件

例如：Spring Security、Shiro、JWT等

##### 了解应用的身份验证机制。确保知道它们是什么以及是如何使用的

##### 在可能的情况下，实施多因素身份验证

#### 参考链接

https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/

### 2.3 失效的对象属性级授权

#### 风险说明



#### 安全实践



### 2.4 无限制资源消耗

#### 风险说明



#### 安全实践



### 2.5 失效的功能级授权

#### 风险说明



#### 安全实践



### 2.6 服务端请求伪造

#### 风险说明



#### 安全实践





