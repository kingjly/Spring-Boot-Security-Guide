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


- 使用纯文本、非加密或弱散列密码
- 使用弱加密密钥

#### 安全实践

##### 不要在身份验证、令牌生成或密码存储方面重复造轮子。使用业界标准组件

例如：Spring Security、Shiro、JWT等

##### 了解应用的身份验证机制。确保知道它们是什么以及是如何使用的

##### 在可能的情况下，实施多因素身份验证（MFA）

基于google Authenticator 的 MFA参考实现：

```java
package xxx.cn.googleauthenticatordemo.authenticator;

import org.apache.commons.codec.binary.Base32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class GoogleGenerator {

    // 发行者（项目名），可为空，注：不允许包含冒号
    public static final String ISSUER = "xxx.cn";

    // 生成的key长度( Generate secret key length)
    public static final int SECRET_SIZE = 32;

    // Java实现随机数算法
    public static final String RANDOM_NUMBER_ALGORITHM = "SHA1PRNG";

    // 最多可偏移的时间, 假设为2，表示计算前面2次、当前时间、后面2次，共5个时间内的验证码
    static int window_size = 1; // max 17
    static long second_per_size = 30L;// 每次时间长度，默认30秒

    /**
     * 生成一个SecretKey，外部绑定到用户
     *
     * @return SecretKey
     */
    public static String generateSecretKey() {
        SecureRandom sr;
        try {
            sr = SecureRandom.getInstance(RANDOM_NUMBER_ALGORITHM);
            sr.setSeed(getSeed());
            byte[] buffer = sr.generateSeed(SECRET_SIZE);
            Base32 codec = new Base32();
            byte[] bEncodedKey = codec.encode(buffer);
            String ret = new String(bEncodedKey);
            return ret.replaceAll("=+$", "");// 移除末尾的等号
        } catch (NoSuchAlgorithmException e) {
            // should never occur... configuration error
            throw new RuntimeException(e);
        }
    }

    /**
     * 生成二维码所需的字符串，注：这个format不可修改，否则会导致身份验证器无法识别二维码
     *
     * @param user   绑定到的用户名
     * @param secret 对应的secretKey
     * @return 二维码字符串
     */
    public static String getQRBarcode(String user, String secret) {
        if (ISSUER != null) {
            if (ISSUER.contains(":")) {
                throw new IllegalArgumentException("Issuer cannot contain the ':' character.");
            }
            user = ISSUER + ":" + user;
        }
        String format = "otpauth://totp/%s?secret=%s";
        String ret = String.format(format, user, secret);
        if (ISSUER != null) {
            ret += "&issuer=" + ISSUER;
        }
        return ret;
    }

    /**
     * 验证用户提交的code是否匹配
     *
     * @param secret 用户绑定的secretKey
     * @param code   用户输入的code
     * @return 匹配成功与否
     */
    public static boolean checkCode(String secret, int code) {
        Base32 codec = new Base32();
        byte[] decodedKey = codec.decode(secret);
        // convert unix msec time into a 30 second "window"
        // this is per the TOTP spec (see the RFC for details)
        long timeMsec = System.currentTimeMillis();
        long t = (timeMsec / 1000L) / second_per_size;
        // Window is used to check codes generated in the near past.
        // You can use this value to tune how far you're willing to go.
        for (int i = -window_size; i <= window_size; ++i) {
            int hash;
            try {
                hash = verifyCode(decodedKey, t + i);
            } catch (Exception e) {
                // Yes, this is bad form - but
                // the exceptions thrown would be rare and a static
                // configuration problem
                e.printStackTrace();
                throw new RuntimeException(e.getMessage());
                // return false;
            }
            System.out.println("input code=" + code + "; count hash=" + hash);
            if (code == hash) { // addZero(hash)
                return true;
            }
/*            if (code==hash ) {
                return true;
            }*/
        }
        // The validation code is invalid.
        return false;
    }

    private static int verifyCode(byte[] key, long t) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] data = new byte[8];
        long value = t;
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }
        SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signKey);
        byte[] hash = mac.doFinal(data);
        int offset = hash[20 - 1] & 0xF;
        // We're using a long because Java hasn't got unsigned int.
        long truncatedHash = 0;
        for (int i = 0; i < 4; ++i) {
            truncatedHash <<= 8;
            // We are dealing with signed bytes:
            // we just keep the first byte.
            truncatedHash |= (hash[offset + i] & 0xFF);
        }
        truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= 1000000;
        return (int) truncatedHash;
    }

    private static byte[] getSeed() {
        String str = ISSUER + System.currentTimeMillis() + ISSUER;
        return str.getBytes(StandardCharsets.UTF_8);
    }
}

```



```java
package xxx.cn.googleauthenticatordemo.authenticator;

import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

@Service
public class AuthenticatorService {
    private Map<String, String> userKeys = new HashMap<>();

    /**
     * 生成一个secretKey，并关联到用户，
     * 然后返回二维码字符串
     *
     * @param username 用户名
     * @return 二维码字符串
     */
    public String generateAuthUrl(String username) {
        String secret = GoogleGenerator.generateSecretKey();
        // todo: 实际项目中，用户名与secretKey的关联关系应当存储在数据库里，否则变化了，就会无法登录
        userKeys.put(username, secret);
        return GoogleGenerator.getQRBarcode(username, secret);
    }

    /**
     * 根据用户名和输入的code，进行校验并返回成功失败
     *
     * @param username 用户名
     * @param code     输入的code
     * @return 校验成功与否
     */
    public boolean validateCode(String username, int code) {
        // todo: 从数据库里读取该用户的secretKey
        String secret = userKeys.get(username);
        if (!StringUtils.hasLength(secret)) {
            throw new RuntimeException("该用户未使用Google身份验证器注册，请先注册");
        }

        return GoogleGenerator.checkCode(secret, code);
    }
}
```

#### 参考链接

https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/

https://github.com/youbl/study/tree/master/study-codes/google-authenticator-demo

### 2.3 失效的对象属性级授权

#### 风险说明

软件框架有时允许开发人员自动将HTTP请求参数绑定到程序代码变量或对象中，以使开发人员更容易使用该框架。 这有时会造成伤害。攻击者有时会利用这种方法创建开发人员从未打算创建的新参数，进而在程序代码中创建或覆盖新变量或对象。例如在注册用户时，覆盖用户的角色属性，将普通用户提升为管理员。

#### 安全实践

##### 创建包含特定属性的DTO，避免将输入直接绑定到对象

例如，user对象定义为：

```java
public class User {
   private String userid;
   private String password;
   private String email;
   private boolean isAdmin;

   //Getters & Setters
}
```

用户注册DTO定义为：

```java
public class UserRegistrationFormDTO {
 private String userid;
 private String password;
 private String email;
    
 //去除了isAdmin属性，防止注册时将用户修改为管理员

 //Getters & Setters
}
```

##### 使用InitBinder注解，设置绑定对象属性的黑白名单

白名单示例

```java
@Controller
public class UserController
{
    @InitBinder
    public void initBinder(WebDataBinder binder, WebRequest request)
    {
        binder.setAllowedFields(["userid","password","email"]);
    }
...
}
```

黑名单示例

```java
@Controller
public class UserController
{
   @InitBinder
   public void initBinder(WebDataBinder binder, WebRequest request)
   {
      binder.setDisallowedFields(["isAdmin"]);
   }
...
}
```

#### 参考链接

https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization

https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

https://stackoverflow.com/questions/47945383/how-to-fix-mass-assignment-insecure-binder-configuration-api-abuse-structural/48625284#48625284

### 2.4 无限制资源消耗

#### 风险说明

API服务通常需要网络带宽、CPU、内存和存储，以及其他如电子邮件、短信由服务商提供的按量计费的资源。如果攻击者能够通过某种手段造成资源的无限制消耗，将导致拒绝服务或运营成本的激增。

#### 安全实践



#### 参考链接

https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption

### 2.5 失效的功能级授权

#### 风险说明



#### 安全实践



#### 参考链接

https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization

### 2.6 服务端请求伪造

#### 风险说明



#### 安全实践



#### 参考链接

https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery





