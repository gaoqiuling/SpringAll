package cc.mrbird.sso.server.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.CorsFilter;

/**
 * @author MrBird
 */
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private LogoutHandler logoutHandler;
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

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                // CSRF禁用
                .csrf().disable()
                .formLogin()
                .loginPage("/login")  // 自定义登录页面
                .and()
                .authorizeRequests()
                .antMatchers(
                        "/login",
                        "/oauth/token",  // 允许令牌端点访问
                        "/oauth/authorize",  // 允许授权端点访问
                        "/css/**",
                        "/js/**",
                        "/error",
                        "/**/logout"
                ).permitAll()
                .antMatchers(HttpMethod.POST, "/login").permitAll()
                .anyRequest().authenticated()
                .and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/**/logout", "GET"))
                .logoutSuccessHandler(logoutHandler)
                .deleteCookies("JSESSIONID")
                .clearAuthentication(true);
        // 添加CORS过滤器
        http.addFilterBefore(corsFilter, LogoutFilter.class);
    }
}
