# XSS-Detect
一个burpsuite插件，用于被动检测可能存在的XSS漏洞的请求。
后续将完善对于可以请求的xss探针、xss攻击以及DOM型xss检测。

2018-12-26：目前主要完成的是，包括对于url参数、post参数、json格式参数、mutil格式参数的xss检测。开启功能后可以实时更新所有流经proxy与Repeat的请求包，是否这些包中的某个参数可以控制其他响应包的内容，从而造成xss的隐患。

1.使用说明
安装插件后，会新增一个tab，打开检测功能：
![Image text](https://github.com/k-vulner/XSS-Detcet/raw/master/img/sm1.png)
之后，你可以正常使用burp一段时间后，查看该tab，所有标黄的列表示该响应包内带有原先请求包中某个参数的内容，“对应请求包ID”说明是该tab下的哪个请求包，“对应请求包入参”则意味着对应请求包的哪个参数出现在了这个响应包中。
举例：下图的8号响应包中出现了8号请求包中入参entry的内容。其中10号响应包也出现了8号请求包中的entry参数的内容。这时测试人员就可以进一步对8号请求进行测试。
![Image text](https://github.com/k-vulner/XSS-Detcet/raw/master/img/sm2.png)

2.原理
十分简单，将所有请求入参分别赋予随机串发送，对所有响应包进行检查。后续将加入对标黄可疑包进行xss探针等直至自动得到payload，与对所有静态js资源进行代码审计的功能。

若有高见，望不吝赐教。谢谢。
