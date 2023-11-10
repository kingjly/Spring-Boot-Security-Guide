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

## 2、API安全风险防范

### 失效的对象级授权

### 失效的用户身份验证 

### 失效的对象属性级授权

### 无限制资源消耗

### 失效的功能级授权

### 服务端请求伪造





