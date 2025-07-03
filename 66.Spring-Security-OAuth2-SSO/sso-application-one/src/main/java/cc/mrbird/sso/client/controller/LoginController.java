package cc.mrbird.sso.client.controller;

import org.springframework.http.*;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.util.*;

@RestController
public class LoginController {
    @GetMapping("/login")
    public String handleCallback(
            @RequestParam("code") String code,
            @RequestParam(value = "state", required = false) String state) {
        DefaultOAuth2AccessToken token = exchangeCodeForToken(code);
        return token.getValue();
    }

    private DefaultOAuth2AccessToken exchangeCodeForToken(String code) {
        // 1. 创建请求头
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // 2. 添加客户端认证（Basic Auth）
        String clientId = "app-a";
        String clientSecret = "app-a-1234";
        String credentials = clientId + ":" + clientSecret;
        String base64Credentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        headers.add("Authorization", "Basic " + base64Credentials);

        // 3. 构建请求参数
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("code", code);
        params.add("redirect_uri", "http://127.0.0.1:9090/app1/login"); // 必须与注册的URI一致

        // 4. 创建HTTP实体
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        // 5. 发送POST请求到令牌端点
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<Map> response = restTemplate.exchange(
                "http://localhost:8080/server/oauth/token", // 授权服务器令牌端点URL
                HttpMethod.POST,
                request,
                Map.class
        );

        // 6. 解析响应
        if (response.getStatusCode() == HttpStatus.OK) {
            Map<String, Object> tokenMap = response.getBody();
            DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken((String) tokenMap.get("access_token"));

            // 设置令牌属性
            accessToken.setTokenType((String) tokenMap.get("token_type"));
            accessToken.setExpiration(new Date(System.currentTimeMillis() + (Integer) tokenMap.get("expires_in") * 1000L));
            accessToken.setRefreshToken(new DefaultOAuth2RefreshToken((String) tokenMap.get("refresh_token")));
            accessToken.setScope(Collections.singleton((String) tokenMap.get("scope")));

            return accessToken;
        } else {
            throw new RuntimeException("Token exchange failed: " + response.getStatusCode());
        }
    }
}
