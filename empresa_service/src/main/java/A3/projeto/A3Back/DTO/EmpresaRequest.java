package A3.projeto.A3Back.DTO;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import jakarta.validation.constraints.Pattern;

public class EmpresaRequest {

    @NotBlank(message = "Usuário é obrigatório")
    @Size(max = 80, message = "Usuário deve ter no máximo 80 caracteres")
    private String usuario;

    @NotBlank(message = "CNPJ é obrigatório")
    @Pattern(regexp = "\\d{14}", message = "CNPJ deve ter 14 dígitos numéricos")
    private String cnpj;

    @NotBlank(message = "Senha é obrigatória")
    private String password;

    // Getters e setters
    public String getUsuario() { return usuario; }
    public void setUsuario(String usuario) { this.usuario = usuario; }

    public String getCnpj() { return cnpj; }
    public void setCnpj(String cnpj) { this.cnpj = cnpj; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
}
