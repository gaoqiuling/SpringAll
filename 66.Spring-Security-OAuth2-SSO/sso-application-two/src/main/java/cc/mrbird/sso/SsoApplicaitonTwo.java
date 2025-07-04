package cc.mrbird.sso;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

/**
 * @author MrBird
 */
@SpringBootApplication
public class SsoApplicaitonTwo {
    public static void main(String[] args) {
        new SpringApplicationBuilder(SsoApplicaitonTwo.class).run(args);
    }
}
