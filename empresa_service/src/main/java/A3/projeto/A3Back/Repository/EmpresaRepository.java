package A3.projeto.A3Back.Repository;

import java.util.Optional;
import org.springframework.data.repository.CrudRepository;
import A3.projeto.A3Back.model.EmpresaModel;

public interface EmpresaRepository extends CrudRepository<EmpresaModel, Integer> {
    boolean existsByUsuario(String usuario);
    boolean existsByCnpj(String cnpj);

    Optional<EmpresaModel> findByUsuario(String usuario);
}

