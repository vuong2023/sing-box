# sing-box

The universal proxy platform.

[![Packaging status](https://repology.org/badge/vertical-allrepos/sing-box.svg)](https://repology.org/project/sing-box/versions)

## Documentation

https://sing-box.sagernet.org

## Support

https://community.sagernet.org/c/sing-box/

## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
```

## 额外功能

### MultiAddr 出站

编译时加入 tag with_multiaddr

支持随机不同 IP:Port 连接，只需要将 Detour 设置为这个出站，即可随机使用不同的 IP:Port 组合连接，需要配合其他出站使用，~~可以躲避基于目的地址的审查~~

```
{
    "tag": "multiaddr-out",
    "type": "multiaddr",
    "addresses": [ // 地址重写规则
        {
            "ip": "100.64.0.1", // IP 地址，与 cidr 两者只能设置一个
            "cidr": "100.64.0.0/10", // CIDR，会从中随机选择 IP，与 ip 两者只能设置一个
            "port": 80, // 连接端口，与 port_range 两者只能设置一个
            "port_range": ":3000" // 连接端口范围，与 port 两者只能设置一个，格式：:3000，4000-5000，5000:
        }
    ],
    // Dial Fields
}
```

用法1：IPv6 + 多端口

* 需要在服务端使用 iptables 做好映射

```iptables -A PREROUTING -t nat -i eth0 -p tcp --dport 8000:9000 -j REDIRECT --to-port 6000```

```
[
    {
        "tag": "proxy-out",
        "type": "xxxx",
        ...
        "detour": "multiaddr-out"
    },
    {
        "tag": "multiaddr-out",
        "type": "multiaddr",
        "addresses": [
            {
                "cidr": "2001:db8::/32",
                "port_range": "8000:9000"
            }
        ]
    }
]
```

用法2：配合 WS + CloudFlare CDN **（请勿滥用，后果自负）**

```
[
    {
        "tag": "ws-out",
        "type": "vmess",
        ...
        "transport": {
            "type": "ws",
            ...
        },
        "detour": "multiaddr-out"
    },
    {
        "tag": "multiaddr-out",
        "type": "multiaddr",
        "addresses": [
            {
                "cidr": "104.21.0.0/24",
                "port": 80
            },
            {
                "cidr": "104.22.0.0/24",
                "port": 80
            },
            {
                "cidr": "104.23.0.0/24",
                "port": 80
            },
            {
                "cidr": "104.21.0.0/24",
                "port": 2095
            },
            {
                "cidr": "104.22.0.0/24",
                "port": 2095
            },
            {
                "cidr": "104.23.0.0/24",
                "port": 2095
            }
        ]
    }
]
```
