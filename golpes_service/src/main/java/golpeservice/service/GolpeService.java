package golpeservice.service;

import golpeservice.model.GolpeModel;
import golpeservice.repository.GolpeRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class GolpeService {

    private final GolpeRepository golpeRepository;

    public GolpeService(GolpeRepository golpeRepository) {
        this.golpeRepository = golpeRepository;
    }

    // 📌 Cadastro de golpes
    public GolpeModel cadastrarGolpe(GolpeModel golpe) {
        if (golpe.getEmpresa() == null || golpe.getEmpresa().trim().isEmpty()) {
            throw new IllegalArgumentException("O nome da empresa é obrigatório");
        }
        golpe.setEmpresa(golpe.getEmpresa().trim().toUpperCase());
        return golpeRepository.save(golpe);
    }

    // 📌 Listar todos os golpes
    public List<GolpeModel> listarTodos() {
        return golpeRepository.findAll();
    }

    // 📌 Listar golpes por empresa
    public List<GolpeModel> listarPorEmpresa(String nome) {
        return golpeRepository.findByEmpresaIgnoreCase(nome.trim().toUpperCase());
    }

    // ✏️ Atualizar golpe (ADMIN)
    public GolpeModel atualizarGolpe(Integer id, GolpeModel dadosAtualizados) {
        GolpeModel golpe = golpeRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Golpe não encontrado"));

        golpe.setDescricao(dadosAtualizados.getDescricao());
        golpe.setEmpresa(dadosAtualizados.getEmpresa().trim().toUpperCase());
        golpe.setEmpresaId(dadosAtualizados.getEmpresaId());

        return golpeRepository.save(golpe);
    }

    // 🗑️ Excluir golpe (ADMIN)
    public void excluirGolpe(Integer id) {
        if (!golpeRepository.existsById(id)) {
            throw new RuntimeException("Golpe não encontrado");
        }
        golpeRepository.deleteById(id);
    }
}
