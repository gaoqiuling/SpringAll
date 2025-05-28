package cc.mrbird.sso.server.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Component
public class LogoutHandler implements LogoutSuccessHandler {

    private final TokenStore tokenStore;

    public LogoutHandler(TokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, 
            Authentication authentication) throws IOException, ServletException {
        // 获取当前认证信息
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getDetails() != null) {
            // 清除token
            String token = request.getHeader("Authorization");
            if (token != null && token.startsWith("Bearer ")) {
                token = token.substring(7);
                tokenStore.removeAccessToken(tokenStore.readAccessToken(token));
            }
        }

        // 清除会话
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        // 清除安全上下文
        SecurityContextHolder.clearContext();
        // 重定向到登录页面
        response.sendRedirect("/login?logout");
    }
} 