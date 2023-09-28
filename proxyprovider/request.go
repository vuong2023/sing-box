package proxyprovider

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/proxyprovider/clash"
)

func request(ctx context.Context, httpClient *http.Client, url string) (*Cache, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "clash.meta")

	req = req.WithContext(ctx)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	buffer := bytes.NewBuffer(nil)
	_, err = io.Copy(buffer, resp.Body)
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	resp.Body.Close()

	outbounds, err := clash.ParseClashConfig(buffer.Bytes())
	if err != nil {
		return nil, err
	}

	var clashInfo ClashInfo
	var ok bool
	subscriptionUserInfo := resp.Header.Get("subscription-userinfo")
	if subscriptionUserInfo != "" {
		subscriptionUserInfo = strings.ToLower(subscriptionUserInfo)
		regTraffic := regexp.MustCompile(`upload=(\d+); download=(\d+); total=(\d+)`)
		matchTraffic := regTraffic.FindStringSubmatch(subscriptionUserInfo)
		if len(matchTraffic) == 4 {
			uploadUint64, err := strconv.ParseUint(matchTraffic[1], 10, 64)
			if err == nil {
				clashInfo.Upload = uploadUint64
				ok = true
			}
			downloadUint64, err := strconv.ParseUint(matchTraffic[2], 10, 64)
			if err == nil {
				clashInfo.Download = downloadUint64
				ok = true
			}
			totalUint64, err := strconv.ParseUint(matchTraffic[3], 10, 64)
			if err == nil {
				clashInfo.Total = totalUint64
				ok = true
			}
		}
		regExpire := regexp.MustCompile(`expire=(\d+)`)
		matchExpire := regExpire.FindStringSubmatch(subscriptionUserInfo)
		if len(matchExpire) == 2 {
			expireUint64, err := strconv.ParseUint(matchExpire[1], 10, 64)
			if err == nil {
				clashInfo.Expire = time.Unix(int64(expireUint64), 0)
				ok = true
			} else {
				clashInfo.Expire = time.Unix(4102358400, 0)
			}
		}
	}

	cache := &Cache{
		Outbounds:  outbounds,
		LastUpdate: time.Now(),
	}
	if ok {
		cache.ClashInfo = &clashInfo
	}

	return cache, nil
}
