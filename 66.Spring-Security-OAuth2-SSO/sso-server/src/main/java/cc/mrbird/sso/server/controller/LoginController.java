package cc.mrbird.sso.server.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
public class LoginController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    @GetMapping("/user/login")
    public String login() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated() && !"anonymousUser".equals(authentication.getPrincipal())) {
            return "redirect:/oauth/authorize";
        }
        return "login";
    }

    @PostMapping("/user/dologin")
    public String login(@RequestParam String username,
                        @RequestParam String password,
                        HttpServletRequest request,
                        HttpServletResponse response,
                        RedirectAttributes redirectAttributes) {
        try {
            // 1. 获取用户信息
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            
            // 2. 创建认证token
            UsernamePasswordAuthenticationToken authenticationToken = 
                new UsernamePasswordAuthenticationToken(username, password);
            // 3. 进行认证
            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            // 4. 认证成功，将认证信息存入SecurityContext
            SecurityContextHolder.getContext().setAuthentication(authentication);
            // 5. 获取重定向URI
            String redirectUri = request.getParameter("redirect_uri");
            if (redirectUri != null && !redirectUri.isEmpty()) {
                return "redirect:" + redirectUri;
            }
            // 6. 默认重定向到授权页面
            return "redirect:/oauth/authorize";
            
        } catch (Exception e) {
            // 认证失败，返回登录页面并显示错误信息
            redirectAttributes.addFlashAttribute("error", "登录失败：" + e.getMessage());
            return "redirect:/user/login?error";
        }
    }
} 