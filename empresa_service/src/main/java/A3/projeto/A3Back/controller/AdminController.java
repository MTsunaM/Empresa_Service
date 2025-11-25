package A3.projeto.A3Back.controller;

import A3.projeto.A3Back.Repository.EmpresaRepository;
import A3.projeto.A3Back.model.EmpresaModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @Autowired
    private EmpresaRepository empresaRepository;

    @Autowired
    private RestTemplate restTemplate; // comunicação com golpe_service

    // 🔎 Consultar todas as empresas
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/empresas")
    public Iterable<EmpresaModel> listarEmpresas() {
        return empresaRepository.findAll();
    }

    // 🔎 Consultar empresa específica
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/empresas/{id}")
    public EmpresaModel buscarEmpresaPorId(@PathVariable Integer id) {
        return empresaRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Empresa não encontrada"));
    }

    // ✏️ Atualizar dados da empresa
    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/empresas/{id}")
    public EmpresaModel atualizarEmpresa(@PathVariable Integer id, @RequestBody EmpresaModel dadosAtualizados) {
        EmpresaModel empresa = empresaRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Empresa não encontrada"));

        empresa.setUsuario(dadosAtualizados.getUsuario());
        empresa.setCnpj(dadosAtualizados.getCnpj());
        empresa.setAtivo(dadosAtualizados.isAtivo());
        empresa.setRole(dadosAtualizados.getRole());

        return empresaRepository.save(empresa);
    }

    // 🚫 Desativar empresa
    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/empresas/{id}/desativar")
    public EmpresaModel desativarEmpresa(@PathVariable Integer id) {
        EmpresaModel empresa = empresaRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Empresa não encontrada"));

        empresa.setAtivo(false);
        return empresaRepository.save(empresa);
    }

    // 🗑️ Excluir empresa
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/empresas/{id}")
    public ResponseEntity<String> excluirEmpresa(@PathVariable Integer id) {
        if (!empresaRepository.existsById(id)) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Empresa não encontrada");
        }
        empresaRepository.deleteById(id);
        return ResponseEntity.ok("Empresa excluída com sucesso");
    }

    // 🔎 Consultar golpes (via golpe_service)
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/golpes")
    public List<Object> listarGolpes() {
        String url = "http://localhost:8082/api/golpes"; // ajuste para a porta do golpe_service
        return restTemplate.getForObject(url, List.class);
    }

    // 🗑️ Excluir golpe (via golpe_service)
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/golpes/{id}")
    public ResponseEntity<String> excluirGolpe(@PathVariable Integer id) {
        String url = "http://localhost:8082/api/golpes/" + id;
        restTemplate.delete(url);
        return ResponseEntity.ok("Golpe excluído com sucesso");
    }
}