# DNS_tunnel

MCWD

## 特征

### 特征选取

#### 单个报文特征

* 子域名长度

* 大写字母数

* 子域名信息熵

  ```python
  def shannon(word):
      entropy = 0.0
      length = len(word)
      occ = {}
      for c in word:
          if not c in occ:
              occ[ c ] = 0
          occ += 1
  
      for (k,v) in occ.iteritems():
          p = float( v ) / float(length)
          entropy -= p * math.log(p, 2)	# Log base 2
      return entropy
  ```

* 二级域名后最长元音距：[基于日志统计特征的DNS隧道检测](https://www.zjujournals.com/eng/article/2020/1008-973X/202009011.shtml)



#### 行为特征

* 一定时间内、对同一二级域名请求数
* 响应时间（正常DNS请求通常会缓存命中，响应时间较短）
* 有效载荷的上传下载比

### 分析方法

* 孤立森林算法，离群度较大的报文可疑：python实现（√）
* 手动设定各特征的阈值，加权和越大越可疑：c++实现（×）



### 实现

* PacketAnalyzer根据解析的DNS报文计算各种单个报文特征
* 对于行为特征，记录每个请求的transactionID和报文对并保存，得到响应报文时根据transactionID查找之前保存的请求报文，得到请求-响应对，计算响应时间和有效载荷的上传下载比；同时用滑动窗口维护每个二级域名的最近请求数。
* 得到的特征，用孤立森林算法计算离群度

## 各文件文档（已废弃）

### main.cpp

主函数打开pcap文件，设置libpcap过滤器，只处理DNS报文，即端口号为53的UDP报文。调用`pcap_loop`函数，每次捕获到一个DNS报文，就调用`packetHandler`函数进行处理。

`packetHandler`函数对于每个报文，首先从报文首字节增加以太网帧头部偏移量以跳过以太网帧头部，然后读取IP头部，判断是否为IPv4。如果是，则再偏移ip头长度，读取UDP头部，判断是否为53端口。注意此处需要用ntoh函数将ip头中的协议字段的字节从网络序转换为主机序。分别打印IP头部和UDP头部信息。

若是53端口，则再偏移udp头长度，得到DNS报文。传入DNS_Packet构造函数中解析，构造DNS_Packet对象。然后调用DNS_Packet对象的`display`函数打印报文信息。

### DNS.h

定义了DNS报文的各个字段，包括DNS报文的基本信息、查询字段、回答字段、资源记录字段。定义了DNS报文的各个字段的类，包括DNS_Base、DNS_Queries、DNS_Query、DNS_RRs、DNS_Resource_Record。定义了域名类DomainName，用于保存域名。

1. 
    DNS_Packet类，保存DNS报文的各个字段，其构造函数解析原始DNS报文，构造格式化的DNS请求或响应。DNS_Packet类有成员变量：

    ```c++
    DNS_Base base;
    DNS_Queries queries;
    std::array<DNS_RRs, 3> RRs_3;
    ```

    其中DNS_Base类保存DNS报文的基本信息，DNS_Queries类保存DNS报文的查询字段，DNS_RRs类保存DNS报文的回答字段。3个DNS_RRs对象分别保存DNS报文的回答字段、授权回答字段和附加信息字段。

2. 
    DNS_Base类有成员变量：

    ```c++
    uint16_t transactionID;
    uint16_t flags;
    uint16_t questions;
    std::array<uint16_t, 3> RRs_num;
    ```

    其中transactionID保存事务ID，flags保存标志位，questions保存问题数，RRs_num三项分别保存回答数、授权回答数和附加信息数。

3. 
    DNS_Queries类有成员变量：

    ```c++
    typedef std::vector<std::unique_ptr<DNS_Query>> Queries;
    Queries queries;
    ```

    其中queries保存查询（Query）数组，每项是一个DNS_Query对象。

4. 
    DNS_Query类有成员变量：

    ```c++
    DomainName domainName;
    QueryType queryType;
    uint16_t queryClass;    // 1
    ```

    其中domainName保存域名，queryType保存查询类型，queryClass保存查询类，通常为1，表示TCP/IP 互联网地址。

5. 
    DNS_RRs类有成员变量：

    ```c++
    typedef std::vector<std::unique_ptr<DNS_Resource_Record>> RRs_T;
    enum Type { ANSWER, AUTHORITY, ADDITIONAL } type;
    static constexpr std::array<const char*, 3> type_s = {"ANSWER", "AUTHORITY", "ADDITIONAL"};
    RRs_T RRs;
    ```

    其中RRs保存资源记录（Resource Record）数组，type保存RRs类型，type_s保存RRs类型的字符串表示，类型包括回答字段、授权回答字段和附加信息字段。

6. 
    DNS_Resource_Record类有成员变量：

    ```c++
    DomainName domainName;
    QueryType queryType;
    uint16_t queryClass;  // 1
    uint32_t timeToLive;
    uint16_t dataLen;
    const char* data;
    DomainName dataDomainName;
    ```

    其中domainName保存域名，queryType保存查询类型，queryClass保存查询类，timeToLive保存生存时间，dataLen保存数据长度，data保存数据。如果data中的内容是域名，则dataDomainName保存数据域名。

7. 
    DomainName类有成员变量：

    ```c++
    std::vector<std::string> labels;
    ptrdiff_t offset;
    bool isOffset;
    ```

    其中labels保存域名各个标签，offset保存偏移量，isOffset表示本域名对象是否包含偏移量，即是否是压缩域名。压缩域名包括全部压缩域名和部分压缩域名，也可处理递归偏移量的情况，具体见[域名压缩](https://blog.csdn.net/muyangzhe123/article/details/41622461)。
    
    构造对象时，传入原始DNS报文中的域名起始字节。如果是非压缩域名，则调用parseLabels成员函数解析域名，将各个标签保存在labels中。如果是压缩域名，则保存偏移量offset，将isOffset置为true。待DNS_Packet对象构造完成后，再调用`parseOffset`函数递归解析DNS_Packet->RRs_3的各Resource_Record中的压缩域名，将labels中的标签补充完整；同时解析其中是压缩域名的data字段。解析算法见DNS.cpp中的[`parseOffset`函数]()和[`parseLabels`函数]()。

### DNS.cpp

定义了DNS_Packet类的构造函数和成员函数，以及DNS_Packet类的成员变量的构造函数和成员函数。

#### DNS_Packet::DNS_Packet

DNS_Packet类的构造函数传入原始DNS报文，解析报文，构造格式化的DNS请求或响应。构造函数首先解析DNS报文的基本信息，并将报文偏移到问题部分。根据基本信息中的问题数，循环解析问题部分，构造DNS_Query对象，保存在DNS_Queries对象中。然后根据基本信息中的回答数、授权回答数和附加信息数，循环解析回答部分、授权回答部分和附加信息部分，构造DNS_Resource_Record对象，保存在DNS_RRs对象中。

#### DomainName::parseOffset

`parseOffset`函数传入传入原始DNS报文。当本对象为压缩域名时，将原始DNS报文加上偏移量，得到压缩域名的起始字节，判断是否为压缩域名，如果是，则更新offset为新的偏移量，递归调用`parseOffset`函数解析偏移量，直到解析到非压缩域名为止。如果不是，则调用`parseLabels`函数解析域名，将各个标签保存在labels中。

#### DomainName::parseLabels

构造域名对象时，传入原始DNS报文中域名起始字节，读取第一个字节，判断其高两位是否均为1，如果是，则表示是压缩域名，再读取一字节，将其和第一字节低6位合并作为偏移量保存在offset中，并将isOffset置为true，等待调用parseOffset函数解析偏移量。如果不是，则表示是非压缩域名，将isOffset置为false，调用`parseLabels`函数解析域名，将各个标签保存在labels中。

`parseLabels`函数传入原始DNS报文中的域名起始字节，读取第一个字节，同上述一样判断是否为压缩域名，如果是，则说明为域名部分压缩，仍像上述一样置isOffset和offset字段，并返回，等待调用parseOffset函数解析偏移量。如果不是，则将该字节作为下一标签长度len，再读取len字节，作为下一个标签的内容。如果标签长度为0，则表示域名解析结束，返回。循环上述步骤，直到len为0，域名解析结束。
