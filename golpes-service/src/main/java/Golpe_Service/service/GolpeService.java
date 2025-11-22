package Golpe_Service.service;


import Golpe_Service.model.GolpeModel;
import Golpe_Service.repository.GolpeRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class GolpeService {

    private final GolpeRepository golpeRepository;

    public GolpeService(GolpeRepository golpeRepository) {
        this.golpeRepository = golpeRepository;
    }

    public GolpeModel cadastrarGolpe(GolpeModel golpe) {
        if (golpe.getEmpresa() == null || golpe.getEmpresa().trim().isEmpty()) {
            throw new IllegalArgumentException("O nome da empresa é obrigatório");
        }
        golpe.setEmpresa(golpe.getEmpresa().trim().toUpperCase());
        return golpeRepository.save(golpe);
    }

    public List<GolpeModel> listarTodos() {
        return golpeRepository.findAll();
    }

    public List<GolpeModel> listarPorEmpresa(String nome) {
        return golpeRepository.findByEmpresaIgnoreCase(nome);
    }
}

