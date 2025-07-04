package cc.mrbird.sso.client.controller;

import org.springframework.http.*;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;
import java.util.Collections;
import java.util.Map;

@RestController
public class LoginController {
    @GetMapping("/login")
    public String handleCallback(
            @RequestParam("code") String code,
            @RequestParam(value = "state", required = false) String state) {
        OAuth2AccessTokenResponse token = exchangeCodeForToken(code);
        return token.getAccessToken().getTokenValue();
    }

    private OAuth2AccessTokenResponse exchangeCodeForToken(String code) {
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

        if (response.getStatusCode() != HttpStatus.OK) {
            throw new RuntimeException("Token exchange failed: " + response.getStatusCode());
        }
        Map<String, Object> tokenMap = response.getBody();
        // 1. 构造 Token 响应对象
        OAuth2AccessTokenResponse tokenResponse =
                OAuth2AccessTokenResponse.withToken((String) tokenMap.get("access_token"))
                        .tokenType(OAuth2AccessToken.TokenType.BEARER) // 默认类型
                        .expiresIn((Integer) tokenMap.get("expires_in")) // 过期时间
                        .refreshToken((String) tokenMap.get("refresh_token")) // 刷新令牌
                        .scopes(Collections.singleton((String) tokenMap.get("scope"))) // 权限范围
                        .build();

        return tokenResponse;
    }
}
