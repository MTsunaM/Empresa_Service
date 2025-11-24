package golpeservice.repository;



import golpeservice.model.GolpeModel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface GolpeRepository extends JpaRepository<GolpeModel, Integer> {
    List<GolpeModel> findByEmpresaId(Integer empresaId);
    List<GolpeModel> findByEmpresaIgnoreCase(String empresa);
    List<GolpeModel> findByEmpresaContainingIgnoreCase(String empresa);
}


