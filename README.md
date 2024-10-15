# Re:filter

![blackandgreen_A_preview_git](https://github.com/user-attachments/assets/8edb734f-7ddf-4dc8-a08f-9c94b707109f)

**Re:filter** — это попытка создать актуальный список заблокированных доменов и IP-адресов в РФ, а также популярных и заблокированных для пользователей из России. Этот репозиторий содержит весь исходный код для процесса фильтрации списка доменов РКН, и (в будущем: регулярные) выпуски:

- **V2Fly, Xray**: `geoip.dat`, `geosite.dat`
- **Sing-Box**: `geoip.db`, `geosite.db`+ .srs файлы
- Отфильтрованные списки доменов: `domains_all.lst`
- Суммированный список IP-адресов: `ipsum.lst`
- **Публичный BGP сервер**, где используется суммированный список IP-адресов: `165.22.127.207` (AS 65412)

## Пример использования Xray

```json
{
  "routing": {
    "rules": [
      {
        "ip": [
          "ext:geoip.dat:refilter"
        ],
        "type": "field",
        "outboundTag": "proxy"
      },
      {
        "domain": [
          "ext:geosite.dat:refilter"
        ],
        "type": "field",
        "outboundTag": "proxy"
      },
      {
        "type": "field",
        "outboundTag": "direct"
      }
    ]
  }
}
```
Пример RoutingA для V2RayA:  
`default: direct`  
`ip(geoip:refilter)->proxy`  
`domain(ext:"LoyalsoldierSite.dat:refilter")->proxy`  


## Пример использования Sing-Box
```json
{
  "route": {
    "final": "direct",
    "auto_detect_interface": true,
    "rules": [
      {
        "rule_set": [
          "refilter_domains",
          "refilter_ipsum"
        ],
        "outbound": "proxy"
      }
    ],
    "rule_set": [
      {
        "tag": "refilter_domains",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/1andrevich/Re-filter-lists/releases/latest/download/ruleset-domain-refilter_domains.srs",
        "download_detour": "direct"
      },
      {
        "tag": "refilter_ipsum",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/1andrevich/Re-filter-lists/releases/latest/download/ruleset-ip-refilter_ipsum.srs",
        "download_detour": "direct"
      }
    ]
  },
  "experimental": {
    "cache_file": {
      "enabled": true
    }
  }
}
```

## Пример конфигурации bird2 (/etc/bird.conf)

```
log syslog all;
log stderr all;

router id $IP;

protocol device {
    scan time 300;
}

protocol kernel kernel_routes {
    scan time 60;
    ipv4 {
        import none;
        export all;
    };
}

protocol bgp refilter {
    ipv4 {
        import filter {
            #gw = $IP_GATEWAY;
            ifname = "$INTERFACE";
            accept;
        };
        export none;
    };
    local as 64999;
    neighbor 165.22.127.207 as 65412;
    multihop;
    hold time 240;
}
```
---

**Re:filter** is an attempt to create a relevant list of blocked domains and IPs in Russia, along with popular domains that are also blocked for Russian users. This repository contains all the source code for the RKN domain list filtration process, and (TBD: regular) releases of:

- **V2Fly, Xray**: `geoip.dat`, `geosite.dat`
- **Sing-Box**: `geoip.db`, `geosite.db` + .srs rulesets
- Filtered lists of domains: `domains_all.lst`
- Summarized IP list: `ipsum.lst`
- **Public BGP Server** where the summarized IP list is used: `165.22.127.207` (AS 65412)

## Xray config example

```json
{
  "routing": {
    "rules": [
      {
        "ip": [
          "ext:geoip.dat:refilter"
        ],
        "type": "field",
        "outboundTag": "proxy"
      },
      {
        "domain": [
          "ext:geosite.dat:refilter"
        ],
        "type": "field",
        "outboundTag": "proxy"
      },
      {
        "type": "field",
        "outboundTag": "direct"
      }
    ]
  }
}
```
RoutingA of V2RayA Example:  
`default: direct`  
`ip(geoip:refilter)->proxy`  
`domain(ext:"LoyalsoldierSite.dat:refilter")->proxy`  


## Sing-box config example

```json
{
  "route": {
    "final": "direct",
    "auto_detect_interface": true,
    "rules": [
      {
        "rule_set": [
          "refilter_domains",
          "refilter_ipsum"
        ],
        "outbound": "proxy"
      }
    ],
    "rule_set": [
      {
        "tag": "refilter_domains",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/1andrevich/Re-filter-lists/releases/latest/download/ruleset-domain-refilter_domains.srs",
        "download_detour": "direct"
      },
      {
        "tag": "refilter_ipsum",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/1andrevich/Re-filter-lists/releases/latest/download/ruleset-ip-refilter_ipsum.srs",
        "download_detour": "direct"
      }
    ]
  },
  "experimental": {
    "cache_file": {
      "enabled": true
    }
  }
}
```

## bird2 config example (/etc/bird.conf)

```
log syslog all;
log stderr all;

router id $IP;

protocol device {
    scan time 300;
}

protocol kernel kernel_routes {
    scan time 60;
    ipv4 {
        import none;
        export all;
    };
}

protocol bgp refilter {
    ipv4 {
        import filter {
            #gw = $IP_GATEWAY;
            ifname = "$INTERFACE";
            accept;
        };
        export none;
    };
    local as 64999;
    neighbor 165.22.127.207 as 65412;
    multihop;
    hold time 240;
}
```


