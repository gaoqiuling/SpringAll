package cc.mrbird.sso.server.config;

import cc.mrbird.sso.server.service.UserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

/**
 * @author MrBird
 */
@Configuration
@EnableAuthorizationServer
public class SsoAuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private TokenStore jwtTokenStore;
    @Autowired
    private JwtAccessTokenConverter jwtAccessTokenConverter;
    @Autowired
    private UserDetailService userDetailService;
    @Autowired
    private TokenEnhancerChain tokenEnhancerChain;
    @Autowired
    private PasswordEncoder passwordEncoder;

    //    客户端身份验证：决定客户端是否有资格请求令牌。
//    存储方式：可以通过内存（inMemory()）、JDBC（jdbc()）或自定义实现。
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("app-a")
                .secret(passwordEncoder.encode("app-a-1234"))
                .authorizedGrantTypes("refresh_token", "authorization_code")
                .accessTokenValiditySeconds(3600)
                .refreshTokenValiditySeconds(86400)
                .scopes("all")
                .autoApprove(true)
                .redirectUris("http://127.0.0.1:9090/app1/login")
                .and()
                .withClient("app-b")
                .secret(passwordEncoder.encode("app-b-1234"))
                .authorizedGrantTypes("refresh_token", "authorization_code")
                .accessTokenValiditySeconds(7200)
                .scopes("all")
                .autoApprove(true)
                .redirectUris("http://127.0.0.1:9091/app2/login");
    }

    // 作用：配置授权服务器自身的安全规则
//    定义授权服务器端点（如 /oauth/token、/oauth/check_token 等）的安全约束。
//    控制谁可以访问这些端点，例如：
//    允许客户端以表单身份验证（如直接发送 client_id 和 client_secret）。
//    配置令牌端点（/oauth/token）的访问权限。
//    开放公钥端点（/oauth/token_key）或令牌验证端点（/oauth/check_token）。
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) {
        security
                .tokenKeyAccess("isAuthenticated()") // 允许所有人访问 /oauth/token_key（获取公钥）
                .checkTokenAccess("isAuthenticated()") // 需要认证才能访问 /oauth/check_token
                .allowFormAuthenticationForClients() // 允许客户端用表单提交 client_id/client_secret
                .passwordEncoder(passwordEncoder);
    }

    //定义令牌生成、存储及授权流程的具体实现
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints.authenticationManager(authenticationManager)
                .tokenStore(jwtTokenStore)
                .tokenEnhancer(tokenEnhancerChain)
                .accessTokenConverter(jwtAccessTokenConverter)
                .userDetailsService(userDetailService);
    }
}
