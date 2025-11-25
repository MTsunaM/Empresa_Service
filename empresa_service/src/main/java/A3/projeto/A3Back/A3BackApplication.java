package A3.projeto.A3Back;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
public class A3BackApplication {

	public static void main(String[] args) {
		SpringApplication.run(A3BackApplication.class, args);
	}

}
