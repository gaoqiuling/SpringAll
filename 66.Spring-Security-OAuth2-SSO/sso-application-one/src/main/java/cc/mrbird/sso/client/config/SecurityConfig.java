package cc.mrbird.sso.client.config;

import cc.mrbird.sso.client.filter.JwtAuthenticationTokenFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

@Order(Ordered.HIGHEST_PRECEDENCE)
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    @Bean
    public CorsFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        // 设置访问源地址
        config.addAllowedOriginPattern("*");
        // 设置访问源请求头
        config.addAllowedHeader("*");
        // 设置访问源请求方法
        config.addAllowedMethod("*");
        // 有效期 1800秒
        config.setMaxAge(1800L);
        // 添加映射路径，拦截一切请求
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        // 返回新的CorsFilter
        return new CorsFilter(source);
    }

    // 配置 Web 页面访问（高优先级
    @Bean
    @Order(1)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .requestMatchers(requestMatchers -> requestMatchers
                        // 只匹配特定的路径，而不是所有路径
                        .antMatchers("/", "/index.html", "/public/**", "/error", "/login", "/oauth2/**", "/login/oauth2/**")
                )
                .csrf().disable()
                .authorizeHttpRequests(authorize -> authorize
                        // 这些路径全部允许
                        .anyRequest().permitAll()
                )
                .oauth2Login();
        return http.build();
    }

//    // 配置 Web 页面访问（高优先级）
//    @Bean
//    @Order(1)
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .requestMatchers(requestMatchers -> requestMatchers
//                        .antMatchers("/**") // 简单处理所有路径
//                )
//                .csrf().disable()
//                .authorizeHttpRequests(authorize -> authorize
//                        .antMatchers("/", "/index.html", "/public/**", "/error", "/login", "/user/**").permitAll()
//                        .antMatchers("/oauth2/**", "/login/oauth2/**").permitAll()
//                        .anyRequest().authenticated()
//                )
//                .oauth2Login();
//        return http.build();
//    }

    // 配置 API 资源服务器（低优先级）
    @Bean
    @Order(2)
    public SecurityFilterChain apiFilterChain(HttpSecurity http, AuthenticationEntryPointImpl entryPoint, JwtAuthenticationTokenFilter authenticationTokenFilter) throws Exception {
        http
                .requestMatchers(matchers -> matchers
                        .antMatchers("/api/**", "/user/**") // 明确处理 API 路径
                )
                .csrf().disable()
                .exceptionHandling().authenticationEntryPoint(entryPoint).and()
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                .addFilterBefore(authenticationTokenFilter, CorsFilter.class);
        return http.build();
    }


    @Bean
    public JwtDecoder jwtDecoder() {
        SecretKey secretKey = new SecretKeySpec(
                "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ab+cd=".getBytes(StandardCharsets.UTF_8),
                "HmacSHA256"
        );
        return NimbusJwtDecoder.withSecretKey(secretKey).build();
    }
}