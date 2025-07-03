package cc.mrbird.sso;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

/**
 * @author MrBird
 */
@SpringBootApplication
public class SsoApplicaitonOne {

    public static void main(String[] args) {
        new SpringApplicationBuilder(SsoApplicaitonOne.class).run(args);
    }
}
