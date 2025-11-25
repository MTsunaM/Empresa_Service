package A3.projeto.A3Back.Security;

import A3.projeto.A3Back.Repository.EmpresaRepository;
import A3.projeto.A3Back.model.EmpresaModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class EmpresaUserDetailsService implements UserDetailsService {

    @Autowired
    private EmpresaRepository empresaRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        EmpresaModel emp = empresaRepository.findByUsuario(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuário não encontrado"));

        List<SimpleGrantedAuthority> authorities =
                List.of(new SimpleGrantedAuthority("ROLE_" + emp.getRole().name()));

        return new User(
                emp.getUsuario(),
                emp.getPasswordHash(),
                emp.isAtivo(),
                true,
                true,
                true,
                authorities
        );
    }
}