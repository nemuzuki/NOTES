### 第一章 Web安全基础

#### 1.1 绪论

APT（Advanced Persistent Threat）：高级持续性威胁，是黑客以窃取核心资料为目的，针对客户所发动的网络攻击和侵袭行为，常用攻击方法：

- 鱼叉式网络钓鱼：先获取目标用户的一些信息，有针对性地架设钓鱼网站，钓鱼邮件诱导访问
- 水坑攻击：攻击者入侵用户经常访问的网站，植入恶意代码，用户访问时恶意代码执行

利用cookie进行web邮箱登录：攻击者发送包含恶意代码的邮件，教师点开后，代码获取cookie并将其发给攻击者，攻击者可以利用cookie直接登录教师邮箱

0day：已发现未公开，官方无补丁的漏洞

C2：command and control，利用其他网站作为通信控制信道

NFC：手机触碰卡导致访问网站，网站包含攻击代码，手机被控制，向网站反弹一个shell（浏览器漏洞）



#### 1.2 Web的简明历史

Web是一个抽象的信息空间，也是一个分布式系统

Web的技术基础：HTML描述信息资源，URI定位资源，HTTP请求资源

- web1.0：静态网页，用户只能获取信息，没有交互

- web2.0：用户可以提供数据，交互性更强。AJAX（Asynchronous JavaScript and XML），位于浏览器，基于JavaScript的XmlHttpRequest，可以向服务器发送数据，并在客户端采用JavaScript处理服务器响应，更新页面局部信息

- web3.0：代表一种去中心化理念及各种应用，区块链、智能合约、元宇宙

js也可用于服务端，如node.js运行环境，其内置Web服务器，可以与操作系统及文件系统直接交互



浏览器如何渲染网页
1. 处理 HTML 标记并构建 DOM 树。
2. 处理 CSS 标记并构建 CSSOM (CSS Object Model)树。
3. 将 DOM 与 CSSOM 合并成一个渲染树。
4. 根据渲染树来布局，以计算每个节点的几何信息。
5. 将各个节点绘制到屏幕上。

#### 1.3 同源策略

源：协议、域名、端口

同源策略：**浏览器**的一种安全功能，判断两个页面是否同源（协议、域名、端口一致），从而判断一个页面的脚本是否能在另一个页面执行（写页面、共享资源）

浏览器需要同源策略阻止不同源交换数据，不同源的**客户端**脚本在未授权的情况下不能读写对方的资源

##### 同源策略的典型场景

- DOM层面的同源策略：

  - DOM（文档对象模型）是一个可以对树形结构的html标签进行增删改查的api。例如createElement(标签名)可以创建元素节点
  - 限制了来自不同源的”document”对象或js脚本，对当前“document”对象的读取或设置某些属性
  - `<script><img><iframe><link>`等带有src属性的标签可以从不同的域加载和执行资源，不受限制
  - `<iframe>`父子界面受约束
  - `<script>`引入外部JS文件，此JS的源为当前页面

- AJAX层面的同源策略：

  - 严格受同源策略约束，不能随意跨域请求。
  - 使用XMLHttpRequest.open(…)里设定的目的URL，必须与发起页面协议、域名、端口严格相同。
  - 如果请求不同源的url，跨域请求可以正常发出，但浏览器阻止脚本获取返回的内容

- Web storage的同源策略：

  - Web storage是浏览器存储本地数据的一种方案，包括session数据和持久化数据（sessionStorage和localStorage）

  - 如果数据不需要服务端处理，只需要存储在客户端，不需要持续将数据发回服务器
  - 严格遵守同源策略

- 脚本型URL的同源策略：在URL的位置



##### 跨域通信技术

有时两个网站需要跨域共享数据，怎么办捏？

- Server proxy：客户端利用本域服务器作为代理请求跨域服务器，获取域外服务器信息。因为**服务端不存在同源策略**

- document.domain='source'：设置父子页面有共同祖先，这样父页面的js即可动态读取子页面的DOM树。但是在Ajax请求中此方法无效

- JSONP跨域：由于\<script>标签发出的跨域请求不受同源策略约束，所以让\<script>标签指向的js代码里面包含返回的数据。只能用于GET方法

  ```html
  <script type="text/javascript"> 
      function handleResponse(response){
      	console.log(response); 
      } 
  </script>
  <script type="text/javascript"> 
      window.onload = function() {
          var oBtn = document.getElementById('btn');
          oBtn.onclick = function() {
          var script = document.createElement("script"); 
          //获取信息后回调handleResponse函数，输出到控制台
          script.src = "https://api...count=1&callback=handleResponse";
          document.body.insertBefore(script, document.body.firstChild);
          }; 
      }; 
  </script>
  ```

- window.name：window对象是一个全局变量，在窗口（window）的生命周期内，窗口重定向后载入的页面共享window.name

- CORS跨域资源共享：HTML5标准。让remote.net在响应头中授权server.net域读取其返回的数据，使得浏览器可以放行

  ```js
  header("Access-Control-Allow-Origin: http://server.net")
  ```

- Window.postMessage(value, url)：HTML5标准，允许不同源的脚本采用异步方式发送数据

腾讯单点登陆系统跨域劫持：攻击者写一个钓鱼网站，里面设置document.domain='qq.com'，使得不同源的成为同源，读取了插件xiu中的密钥信息，发给攻击者

#### 1.4 HTTP与Cookie

HTTP请求

- 请求头
  - 请求行：方法，URL，版本
  - 首部行：若干键值对，包括host, connection, user-agent, cookie，时间
- 实体主体

HTTP响应

- 响应头
  - 状态行：版本，状态码，短语
  - 首部行
- 实体主体

HTTP安全问题：

- 数据明文传输，可能被监听
- 客户、服务器缺乏身份认证，可能中间人攻击（MITM）。中间人攻击典型工具：Burp Suite

HTTPS：加入了SSL/TLS层，通信前用数字证书身份认证，用非对称密钥分发对称密钥，用对称钥加密信息

数字证书：数字签名+身份信息。CA将用户身份信息（包括用户名，用户公钥，hash算法）的哈希值hash1用CA私钥签名，再配上hash1作为数字证书；浏览器用CA提供的CA公钥解密得到hash2，hash2=hash1则可信

HTTPS安全问题：浏览器默认填充http://，一般情况网站管理员会采用了 301/302 跳转的方式由 HTTP 跳转到 HTTPS，但是这个过程总使用到 HTTP 因此容易发生劫持。解决方法：HSTS，强制客户端（如浏览器）使用HTTPS与服务器创建连接



Cookie：保存在客户端，客户端发送请求时，携带cookie，以维护会话状态。

cookie的Domain属性，指定cookie被绑定到哪台主机上

安全的cookie：用户登录根据信息（包括用户名、IP、UA、expiration、salt等）组合生成token，存储在服务器数据库中；用户发送的token，解密得出用户名、IP等，并与数据库中对应的token比对

### 第二章 Web客户端安全

#### 2.1 OWASP top 10

最严重的安全风险

- 服务端请求伪造SSRF：利用服务器漏洞以服务器的身份发送一条构造好的请求给服务器所在内网
- 安全日志和检测失败：日志分析
- 数据完整性：不安全的反序列化。如果对不可信数据做了反序列化处理，可能执行任意代码
- 认证及验证机制失效：信息战获得密保问题答案，进而获得更多信息
- 易受攻击和已过期的组件
- 安全配置缺陷：默认值不安全
- 不安全的设计：点击劫持
- 注入式攻击：非法数据被输入，欺骗解释器；XML外部实体注入攻击（XXE）：XML可以从外部读取DTD文件，如果将路径换成另一个文件的路径或者端口，就可以用来读取任意文件或者端口扫描
- 加密机制失效
- 权限控制失效

#### 2.2 XSS与CSRF

##### 跨站脚本攻击XSS

XSS：发生在客户端。向Web页面里插入恶意html代码（利用URL或者提交评论、上传文件等），**当用户浏览该网页时，嵌入其中Web里面的html代码会被执行**。

主要是由于Web服务器没有对用户的输入进行有效性验证或验证强度不够，而又轻易地将它们返回给客户端。

- 反射型XSS：用户输入（或者被骗点击了一个链接）包含恶意参数通过浏览器发送给服务器，服务器会将由恶意参数导致的恶意页面反射给浏览器。属于web攻击，不会修改服务器数据
  例如：在url后面直接写嵌入js的html代码，会在客户端执行

  ```html
  http://localhost/test.php?name=<script>alert(/我的名字是张三/)</script>
  ```

- 存储型XSS：上传包含恶意代码的数据到服务器的数据库中，然后服务器返回包含恶意代码的恶意页面给用户，在浏览器处被执行

- DOM-based XSS：js脚本直接在客户端执行，修改了页面的dom节点，与服务端无关

- 持久型客户端XSS：伪造对客户端的响应数据包，将攻击载荷存储在客户端本地，处于休眠状态，用于之后攻击。（属于网络攻击）

script gadget：脚本本来不能执行，过滤了片段后可以执行脚本

##### 服务端请求伪造攻击SSRF

SSRF（Server-side Request Forgery）：攻击者在未能取得服务器所有权限时，利用服务器能够执行恶意代码的漏洞，将服务器作为代理，发送一条构造好的请求给服务器所在内网，可以对内网扫描或者获取内网信息。

XSS可能引发SSRF

例如下面的html代码被执行，会输出window.location

```html
http//192.168.249.131/pic.php?text=<img src=\"xasdasdasd\" onerror=\"document.body.innerHTML=window.location\"/>
```

##### 跨站请求伪造攻击CSRF

CSRF（Cross-Site Request Forgery）：攻击者利用脚本使得被攻击者浏览器不知情地向目标站点发送**伪造请求**，并借用被攻击者的session获得在目标站点上的权限。

例如：银行网站通过GET请求来转账；攻击者构造钓鱼网站，内含恶意代码

```html
<img src=http://www.mybank.com/Transfer.php?toBankId=11&money=1000>
```

如果用户同时打开钓鱼网站和银行网站，就会被迫自动转钱。因此银行最好不要使用GET请求，使用密码



#### 2.3 点击劫持ClickJacking

利用HTML中iframe标签透明、image图片浮动等手段嵌套一个透明不可见的页面，让用户在不知情的情况下，点击页面时实际点击了上面的一个透明页面

可以拿到安卓设备控制权

防御：

- 检查HTML中图片是否导致浮动，如果是绝对位置，就不会挡住其他内容

- XFO（X-FRAME-OPTIONS）：微软提出的http头，里面可以设置域加载的规则，比如SAMEORIGIN只允许同源域加载到iframe

  ```c
  add_header X-Frame-Options "SAMEORIGIN";
  ```

- Frame Busting：通过js代码禁止iframe的嵌套

- sandbox：HTML5中iframe的新属性，加载内容的脚本被禁止执行                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          

#### 2.4 浏览器与扩展安全

网页木马：一个web页面，里面的恶意代码可以链接多次到包含恶意程序的web服务器，用户访问后在后台下载木马并执行

ActiveX：是一个API，提供许多方法/组件供外部组件或程序调用，来在网页中加入特殊功能。这些方法经常会有漏洞，比如堆/栈/缓冲区/整数溢出漏洞，需要构造测试用例进行漏洞挖掘

Adobe Flash Player漏洞挖掘：利用基于文法的变异生成合法的flash测试用例，进行模糊测试

浏览器安全机制：

- 附加组件签名：火狐对组件进行签名，保证来源可靠
- 写异或执行（Write XOR Execute）：能让网页使用内存写入代码或执行代码，但不能同时进行这两种操作，否则可能缓冲区溢出。增加该机制后，即使缓冲区溢出覆盖内存区域，这部分代码也不能被执行

### 第三章 Web服务端安全

#### 3.1 SQL注入

SQL基础

- union：合并两个select语句的结果集
- DATABASE()： 返回当前数据库名

SQL注入：构造畸形的输入，从而改变原查询语句的语义，由于对用户的输入没有或不充分地过滤

注入技巧

- 万能密码：' or 1=1 #

- 错误回显：故意输错，如果网站开启错误回显功能，即可获得有用的错误提示信息

- 盲注：没开启错误回显时，验证注入的SQL是否执行

  - 布尔盲注：通过and不同语句来比较页面返回结果，确定注入点是否存在。例如`id=1 and 1=1`恒为真，所以能返回信息；而`id=1 and 1=2`恒为假，不返回信息
    
  - 时间盲注：将语句执行大量次数，如果延迟响应则注入点存在
  
    ```sql
     id=1 union SELECT 1,BENCHMARK(500000000, MD5('12345'))
    ```

- 猜查询列数：`id=1 order by 2`按照第2列排序，如果能返回结果，而按照第三列返回不了，则说明只有两列

- union跨表查询

- 占位：`select 1,2,name from `比如网页只能显示三列，不能空着前两列，所以让前两列一直输出1,2，用来占位

- INFORMATION_SCHEMA数据库：存放了所有数据库、表、列的信息

sqlmap工具：SQL自动化注入工具

防范：

- 严格区分普通用户和管理员权限
- 严格过滤用户输入
- 使用预编译语句：SQL语句需要先编译，构建语法树、制定执行计划，之后执行；使用预编译后，将语句中的值用占位符?替代，沿用之前编译时的执行计划，用户的输入仅仅只作为对应参数的取值，不能变成SQL指令被执行

#### 3.2 文件上传与文件包含

webshell：用http来管理服务器的接口，是一种网页后门。黑客使用PHP/JSP/ASP等编写后门文件（此时webshell就是恶意脚本），并上传到入侵的服务器，即可使用浏览器来访问后门，得到命令执行环境

文件上传：上传webshell的过程

webshell的类型

- 一句话木马：客户端上传服务器要执行的语句。下面语句把POST传递的参数pass的值作为语句执行，当URL为xxx.php?pass=aaa时，即可执行aaa语句

    ```php
    <?php @eval($_POST['pass']);?>
    ```
- 大马：体积较大的Webshell

漏洞利用方法：

- 如何绕过浏览器的前端文件类型检查：直接在BurpSuite上修改请求里面的文件后缀字段
- 绕过后端文件类型检查：修改文件头。很多文件类型有固定的文件头，服务器只检查文件前n字节，修改文件头即可。例如只让上传jpg文件，就将Webshell的前N个字节，替换为JPG文件头

防御：

- 上传目录设置为不可执行
- 严格判断文件类型
- 随机生成文件名和文件路径



文件包含（File Inclusion）：在一个页面中通过include方法包含（引入）另外一个文件中的代码。但是如果通过变量引入了恶意文件并执行，就会造成文件包含漏洞

- 本地文件包含：打开并包含本地文件 的漏洞，获取文件路径：利用..遍历文件，日志文件。

- 远程文件包含：php的include(url)函数会获取指定文件中存在的所有文本/代码/标记，并复制到使用 include 语句的文件中。

```php
include($_GET['page'].".php");
# 如果page="http://example.com/mm.jpg?"，那么url里问号后面的部分.php会被当成查询字符串，原来的mm.jpg被成功包含
```

防御：

- 避免包含变量
- 设置open_basedir将用户访问文件的范围限制在指定的目录

#### 3.3 XXE与SSRF

XML：扩展标记语言，键值对形式

```xml
<?xml version="1.0"?>
<note name="test">
<to>Tove</to>
<from>Jani</from>
<heading>Reminder</heading>
<body>Don't forget me</body>
</note>
```

DTD（Document Type Definition，文档类型定义）：描述XML标记符的语法规则，用来约束XML文档，表示每个元素里面有什么类型的元素。
DTD中实体有两种：内部和引用，引用即使用&entity来引用一个外部的实体，容易导致引用过来的内容过大

```dtd
<!ELEMENT note (to,from,heading,body)>
<!ELEMENT to (#PCDATA)>
<!ELEMENT from (#PCDATA)>
<!ELEMENT heading (#PCDATA)>
<!ELEMENT body (#PCDATA)>
```

DTD文档构成

```dtd
定义元素 <!ELEMENT 元素名称 (元素内容)>
定义属性 <!ATTLIST 元素名称 属性名称 属性类型 默认值>
内部定义实体 <!ENTITY 实体名称 "实体的值">
外部定义实体 <!ENTITY 实体名称 SYSTEM "URL">
```

DTD可以在XML文档中声明

```dtd
<!DOCTYPE note [
    <!ELEMENT note (to,from,heading,body)>
    <!ELEMENT to (#PCDATA)>
    <!ELEMENT from (#PCDATA)>
    <!ELEMENT heading (#PCDATA)>
    <!ELEMENT body (#PCDATA)>
]>
```

也可以在XML文档中外部引用DTD

```dtd
<!DOCTYPE root-element SYSTEM "DTDfilename">
```



XXE（XML External Entity，XML外部实体注入攻击）：向XML解析器提交一段符合语法的DTD，但能执行一个非授权的操作。可以造成拒绝服务攻击、任意读取文件、SSRF

造成拒绝服务攻击的方法：

- 递归实体扩展：构造递归实体，该实体在解析过程中，会使文件大小以指数形式增多，如 

  ```dtd
  <!ENTITY lol1 "&lol2;">
  <!ENTITY lol2 "&lol1;">
  ```

- 超大实体多次引用：会使文件大小以指数形式增多

任意读取文件：既然XML可以从外部读取DTD文件，那自然想到了将路径换成另一个文件的路径

```dtd
<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

XXE可以导致SSRF（服务端请求伪造攻击），让服务器作为代理操纵内网

```dtd
<!DOCTYPE data SYSTEM "http://192.168.0.11/shutdown">
```

使内网主机关机

#### 3.4 身份认证与访问控制

1.SSO单点登录：即通过一个应用中的安全验证后，再访问其他应用中的受保护资源时，不再需要重新登录验证

2.session

客户端向服务器发起请求创建session时，如果包含sessionID，则可以继续使用会话。session在服务器端，会降低服务器性能；cookie存在客户端，不安全。

session安全风险：

- session劫持：窃取用户的SessionID
- Session Fixation攻击：如果登录前后用户的session id不变，攻击者可以先获得一个id，交给他人去完成认证，然后用id登录他人账户

3.OAuth：让一个网站A去访问其他网站B内容，而不把B的口令给A。例如使用qq账号授权并登录

A拿着用户的授权向B的认证服务器申请令牌，认证服务器认证后发放令牌，A用令牌向B的资源服务器申请资源

OAuth安全风险：

- 部分厂商没有严格参照官方文档，实现了简版OAuth，将攻击者的第三方账户与受害者的应用账户绑定起来，造成CSRF攻击
- 令牌重放攻击

4.Zero Trust零信任：认为对资源的访问，无论主体和资源是否可信，主体和资源之间的信任关系都需要从零开始

#### 3.5 案例分析

DNS安全问题

反射放大式DDoS攻击：攻击者伪造IP使得僵尸主机一起向dns服务器发起查询，查询很短但根dns的输出很大

### 名词总结

XSS：跨站脚本攻击。向Web页面里插入恶意html代码，用户执行

CSRF：跨站请求伪造。攻击者利用脚本使得被攻击者浏览器被迫向目标站点发送**伪造请求**，并借用被攻击者的session获得在目标站点上的权限

SSRF：服务端请求伪造。攻击者在未能取得服务器所有权限时，利用服务器能够执行恶意代码的漏洞，将服务器作为代理，发送一条构造好的请求给服务器所在内网，可以对内网扫描或者获取内网信息。

XXE：外部实体注入攻击。XML向XML解析器提交一段符合语法的DTD，但能执行一个非授权的操作

### 工具

- BurpSuite：拦截网页请求和响应，修改报文，实现中间人攻击。注意无法拦截host=127.0.0.1的网站

- SQLmap：自动化SQL注入

- dirsearch：Kali的工具，扫描目录下文件。-e指定语言，*为所有文件
  ```sh
  dirsearch -u http://180.97.215.50:30007 -e php
  ```

  
