package cc.mrbird.security;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

@RunWith(SpringRunner.class)
@SpringBootTest
public class JwtTest {
    @Autowired
    private JwtTokenStore jwtTokenStore;

    @Test
    public void test() {
        // 请使用新生成的 token
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjdXN0b21fZmllbGQiOiJxaXVxaXV0ZXN0IiwidXNlcl9uYW1lIjoiYWRtaW4iLCJzY29wZSI6WyJhbGwiXSwiZXhwIjoxNzQ4MzM3NTE5LCJhdXRob3JpdGllcyI6WyJhZG1pbiJdLCJqdGkiOiIzYzA0YjEzYi03ZWFhLTQ5ZGQtYWJlZi1jNWVlYjA3NzllNjQiLCJjbGllbnRfaWQiOiJ0ZXN0In0.LKfvQkeOSlXb03-QTjQEhE3q-s5Lqb_2YrJdvqKDE0c";
        try {
            // 使用 JwtTokenStore 读取 token
            OAuth2AccessToken accessToken = jwtTokenStore.readAccessToken(token);
            if (accessToken != null) {
                // 获取自定义属性
                String customField = (String) accessToken.getAdditionalInformation().get("customField");
                System.out.println("Custom field: " + customField);
                
                // 打印所有额外信息
                System.out.println("Additional information: " + accessToken.getAdditionalInformation());
            } else {
                System.out.println("Token is null");
            }
        } catch (Exception e) {
            System.out.println("Token validation failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
