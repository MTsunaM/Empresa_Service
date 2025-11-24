package golpeservice.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
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

    @Column(name = "empresa_id", nullable = false)
    private Integer empresaId;

    @Column(nullable = false, length = 120)
    private String empresa;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;
}
