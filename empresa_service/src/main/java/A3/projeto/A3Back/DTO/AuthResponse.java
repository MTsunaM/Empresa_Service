package A3.projeto.A3Back.DTO;

public class AuthResponse {
    private String token;
    private String usuario;
    private String role;

    public AuthResponse(String token, String usuario, String role) {
        this.token = token;
        this.usuario = usuario;
        this.role = role;
    }

    public String getToken() {
        return token;
    }

    public String getUsuario() {
        return usuario;
    }

    public String getRole() {
        return role;
    }
}
