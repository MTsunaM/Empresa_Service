package A3.projeto.A3Back.DTO;

import java.time.LocalDateTime;

/**
 * Data Transfer Object for scam reports (golpes).
 * This DTO explicitly excludes the CPF field for privacy protection.
 * Companies should not receive personal identification numbers when viewing scam reports.
 */
public class GolpeDTO {
    
    private Integer id;
    private String nome;
    private String cidade;
    private String meioDeContato;
    private String descricao;
    private String emailOuTelefone;
    private String empresa;
    private LocalDateTime createdAt;

    // Default constructor
    public GolpeDTO() {
    }

    // Constructor with all fields
    public GolpeDTO(Integer id, String nome, String cidade, String meioDeContato, 
                    String descricao, String emailOuTelefone, String empresa, 
                    LocalDateTime createdAt) {
        this.id = id;
        this.nome = nome;
        this.cidade = cidade;
        this.meioDeContato = meioDeContato;
        this.descricao = descricao;
        this.emailOuTelefone = emailOuTelefone;
        this.empresa = empresa;
        this.createdAt = createdAt;
    }

    // Getters
    public Integer getId() {
        return id;
    }

    public String getNome() {
        return nome;
    }

    public String getCidade() {
        return cidade;
    }

    public String getMeioDeContato() {
        return meioDeContato;
    }

    public String getDescricao() {
        return descricao;
    }

    public String getEmailOuTelefone() {
        return emailOuTelefone;
    }

    public String getEmpresa() {
        return empresa;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    // Setters
    public void setId(Integer id) {
        this.id = id;
    }

    public void setNome(String nome) {
        this.nome = nome;
    }

    public void setCidade(String cidade) {
        this.cidade = cidade;
    }

    public void setMeioDeContato(String meioDeContato) {
        this.meioDeContato = meioDeContato;
    }

    public void setDescricao(String descricao) {
        this.descricao = descricao;
    }

    public void setEmailOuTelefone(String emailOuTelefone) {
        this.emailOuTelefone = emailOuTelefone;
    }

    public void setEmpresa(String empresa) {
        this.empresa = empresa;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
}
