package Golpe_Service.controller;

import java.util.List;

import Golpe_Service.model.GolpeModel;
import Golpe_Service.repository.GolpeRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class GolpeController {

    private final GolpeRepository golpeRepository;

    public GolpeController(GolpeRepository golpeRepository) {
        this.golpeRepository = golpeRepository;
    }

    @PostMapping("/cadastrogolpes")
    public ResponseEntity<?> cadastrarGolpe(@RequestBody GolpeModel golpe) {
        System.out.println(">>> [GolpeController] Cadastro recebido: " + golpe);

        if (golpe.getEmpresa() == null || golpe.getEmpresa().trim().isEmpty()) {
            System.out.println(">>> [GolpeController] Empresa não informada");
            return ResponseEntity.badRequest().body("O nome da empresa é obrigatório");
        }

        golpe.setEmpresa(golpe.getEmpresa().trim().toUpperCase());
        GolpeModel salvo = golpeRepository.save(golpe);

        System.out.println(">>> [GolpeController] Golpe salvo com ID: " + salvo.getId());
        return ResponseEntity.ok(salvo);
    }

    @GetMapping
    public List<GolpeModel> listarGolpes() {
        return golpeRepository.findAll();
    }

    @GetMapping("/empresa/{nome}")
    public List<GolpeModel> listarPorEmpresa(@PathVariable String nome) {
        return golpeRepository.findByEmpresaIgnoreCase(nome.trim().toUpperCase());
    }
}
