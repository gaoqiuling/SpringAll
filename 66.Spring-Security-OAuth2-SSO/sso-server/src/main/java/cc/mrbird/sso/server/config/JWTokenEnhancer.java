package cc.mrbird.sso.server.config;

import cc.mrbird.sso.server.domain.MyUser;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.util.HashMap;
import java.util.Map;

/**
 * @author MrBird
 */
public class JWTokenEnhancer implements TokenEnhancer {
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        Map<String, Object> additionalInfo = new HashMap<>();
        if(authentication.getPrincipal() instanceof MyUser){
            additionalInfo.put("userName", ((MyUser) authentication.getPrincipal()).getUserName());
        }
        // 添加自定义属性
        additionalInfo.put("customField", "qiuqiutest");
        // 将自定义信息添加到 token 中
        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);
        return accessToken;
    }
}
