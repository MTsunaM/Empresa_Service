package Golpe_Service.model;

import jakarta.persistence.*;
import org.hibernate.annotations.CreationTimestamp;

@Entity
@Table(name = "golpes")
public class GolpeModel {

    public enum MeioDeContato {
        Telefone,
        WhatsApp,
        SMS,
        Email,
        Outros
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(nullable = false, length = 120)
    private String nome;

    @Column(nullable = false, length = 120)
    private String cidade;

    @Column(length = 14, nullable = false)
    private String cpf;

    @Enumerated(EnumType.STRING)
    @Column(name = "meio_contato", nullable = false)
    private MeioDeContato meioDeContato;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String descricao;

    @Column(name = "email_telefone", length = 120, nullable = false)
    private String emailOuTelefone;

    @Column(nullable = false, length = 120)
    private String empresa;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private java.time.LocalDateTime createdAt;

    // getters e setters
    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getNome() {
        return nome;
    }

    public void setNome(String nome) {
        this.nome = nome;
    }

    public String getCidade() {
        return cidade;
    }

    public void setCidade(String cidade) {
        this.cidade = cidade;
    }

    public String getCpf() {
        return cpf;
    }

    public void setCpf(String cpf) {
        this.cpf = cpf;
    }

    public MeioDeContato getMeioDeContato() {
        return meioDeContato;
    }

    public void setMeioDeContato(MeioDeContato meioDeContato) {
        this.meioDeContato = meioDeContato;
    }

    public String getDescricao() {
        return descricao;
    }

    public void setDescricao(String descricao) {
        this.descricao = descricao;
    }

    public String getEmailOuTelefone() {
        return emailOuTelefone;
    }

    public void setEmailOuTelefone(String emailOuTelefone) {
        this.emailOuTelefone = emailOuTelefone;
    }

    public String getEmpresa() {
        return empresa;
    }

    public void setEmpresa(String empresa) {
        this.empresa = empresa;
    }



}
