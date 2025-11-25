package A3.projeto.A3Back.DTO;

import A3.projeto.A3Back.model.EmpresaModel;
import java.time.LocalDateTime;

public class EmpresaResponse {
    private Integer id;
    private String usuario;
    private String cnpj;
    private boolean ativo;
    private String role;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    // Construtor a partir do model
    public EmpresaResponse(EmpresaModel e) {
        this.id = e.getId();
        this.usuario = e.getUsuario();
        this.cnpj = e.getCnpj();
        this.ativo = e.isAtivo();
        this.role = e.getRole().name();
        this.createdAt = e.getCreatedAt();
        this.updatedAt = e.getUpdatedAt();
    }

    // Método estático para conversão
    public static EmpresaResponse fromModel(EmpresaModel e) {
        return new EmpresaResponse(e);
    }

    // Getters
    public Integer getId() { return id; }
    public String getUsuario() { return usuario; }
    public String getCnpj() { return cnpj; }
    public boolean isAtivo() { return ativo; }
    public String getRole() { return role; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }
}
