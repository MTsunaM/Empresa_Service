package A3.projeto.A3Back.config;

import A3.projeto.A3Back.Repository.EmpresaRepository;
import A3.projeto.A3Back.model.EmpresaModel;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
public class DataInitializer {

    @Bean
    CommandLineRunner initDatabase(EmpresaRepository repository) {
        return args -> {
            if (repository.findByUsuario("ADMIN").isEmpty()) {
                EmpresaModel admin = new EmpresaModel();
                admin.setUsuario("ADMIN");
                admin.setPasswordHash(new BCryptPasswordEncoder().encode("senha-padrao"));
                admin.setRole(EmpresaModel.Role.ADMIN);
                admin.setAtivo(true);

                repository.save(admin);
                System.out.println("Admin padrão criado: usuario=ADMIN, senha=senha-padrao");
            }
        };
    }
}