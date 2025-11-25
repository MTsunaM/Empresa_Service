package golpeservice.controller;

import java.util.List;

import golpeservice.model.GolpeModel;
import golpeservice.repository.GolpeRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/golpes")
public class GolpeController {

    private final GolpeRepository golpeRepository;

    public GolpeController(GolpeRepository golpeRepository) {
        this.golpeRepository = golpeRepository;
    }

    // Health check endpoint (no authentication required)
    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("Golpes service is running");
    }

    // 📌 Cadastro de golpes (somente EMPRESA pode registrar)
    @PreAuthorize("hasRole('EMPRESA')")
    @PostMapping
    public ResponseEntity<?> cadastrarGolpe(@RequestBody GolpeModel golpe) {
        if (golpe.getEmpresaId() == null) {
            return ResponseEntity.badRequest().body("O ID da empresa é obrigatório");
        }
        if (golpe.getEmpresa() == null || golpe.getEmpresa().trim().isEmpty()) {
            return ResponseEntity.badRequest().body("O nome da empresa é obrigatório");
        }

        golpe.setEmpresa(golpe.getEmpresa().trim().toUpperCase());
        GolpeModel salvo = golpeRepository.save(golpe);
        return ResponseEntity.ok(salvo);
    }

    // 📌 Listar todos os golpes (somente ADMIN)
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping
    public ResponseEntity<?> listarGolpes() {
        try {
            System.out.println(">>> [GolpeController] Listing all golpes - ADMIN access");
            List<GolpeModel> golpes = golpeRepository.findAll();
            System.out.println(">>> [GolpeController] Found " + golpes.size() + " golpes");
            return ResponseEntity.ok(golpes);
        } catch (Exception e) {
            System.err.println(">>> [GolpeController] Error listing golpes: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error retrieving scam reports: " + e.getMessage());
        }
    }

    // 📌 Buscar golpes por nome da empresa (EMPRESA pode consultar os seus, ADMIN pode consultar todos)
    @PreAuthorize("hasAnyRole('EMPRESA','ADMIN')")
    @GetMapping("/empresa/{nome}")
    public List<GolpeModel> listarPorEmpresa(@PathVariable String nome) {
        return golpeRepository.findByEmpresaIgnoreCase(nome.trim().toUpperCase());
    }

    // 📌 Buscar golpes por ID da empresa
    @PreAuthorize("hasAnyRole('EMPRESA','ADMIN')")
    @GetMapping("/empresa/id/{empresaId}")
    public List<GolpeModel> listarPorEmpresaId(@PathVariable Integer empresaId) {
        return golpeRepository.findByEmpresaId(empresaId);
    }

    // ✏️ Atualizar golpe (somente ADMIN)
    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/{id}")
    public ResponseEntity<?> atualizarGolpe(@PathVariable Integer id, @RequestBody GolpeModel dadosAtualizados) {
        GolpeModel golpe = golpeRepository.findById(id)
                .orElse(null);

        if (golpe == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Golpe não encontrado");
        }

        golpe.setDescricao(dadosAtualizados.getDescricao());
        golpe.setEmpresa(dadosAtualizados.getEmpresa().trim().toUpperCase());
        golpe.setEmpresaId(dadosAtualizados.getEmpresaId());

        GolpeModel atualizado = golpeRepository.save(golpe);
        return ResponseEntity.ok(atualizado);
    }

    // 🗑️ Excluir golpe (somente ADMIN)
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{id}")
    public ResponseEntity<String> excluirGolpe(@PathVariable Integer id) {
        if (!golpeRepository.existsById(id)) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Golpe não encontrado");
        }
        golpeRepository.deleteById(id);
        return ResponseEntity.ok("Golpe excluído com sucesso");
    }
}
