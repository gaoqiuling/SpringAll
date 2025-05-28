package cc.mrbird.sso.server.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.CorsFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author MrBird
 */
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private LogoutHandler logoutHandler;
    @Autowired
    private AuthenticationEntryPointImpl unauthorizedHandler;
    /**
     * 跨域过滤器
     */
    @Autowired
    private CorsFilter corsFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean(name = BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public AuthenticationSuccessHandler statelessSuccessHandler() {
        return (HttpServletRequest request, HttpServletResponse response,
                org.springframework.security.core.Authentication authentication) -> {

            // 获取原始请求的缓存（不使用Session）
            RequestCache requestCache = new HttpSessionRequestCache();
            SavedRequest savedRequest = requestCache.getRequest(request, response);

            String redirectUrl;
            if (savedRequest != null) {
                // 重定向到原始授权请求
                redirectUrl = savedRequest.getRedirectUrl();
            } else {
                // 默认重定向到授权端点
                redirectUrl = "/server/oauth/authorize?response_type=code&client_id=app-a&redirect_uri=http://127.0.0.1:9090/app1/login&scope=all";
            }

            // 清除请求缓存
            requestCache.removeRequest(request, response);
            response.sendRedirect(redirectUrl);
        };
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                // CSRF禁用
                .csrf().disable()
                // 认证失败处理
//                .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
                // 无状态session配置
                // .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .formLogin()
                .loginPage("/user/login")  // 自定义登录页面
                .loginProcessingUrl("/user/dologin")  // 登录处理URL
                // 使用自定义无状态成功处理器
                //  .successHandler(statelessSuccessHandler())
                .and()
                .authorizeRequests()
                .antMatchers(
                        "/user/login",
                        "/user/dologin",
                        "/login",
                        "/oauth/token",  // 允许令牌端点访问
                        "/oauth/authorize",  // 允许授权端点访问
                        "/css/**",
                        "/js/**",
                        "/error"
                ).permitAll()
                .antMatchers(HttpMethod.POST, "/user/dologin").permitAll()
                .anyRequest().authenticated()
                .and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/**/logout", "GET"))
                .logoutSuccessHandler(logoutHandler)
                .clearAuthentication(true);

        // 添加CORS过滤器
        http.addFilterBefore(corsFilter, LogoutFilter.class);
    }
}
