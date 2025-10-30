package hugolini.login.auth.jwt.controller;

import hugolini.login.auth.jwt.model.User;
import hugolini.login.auth.jwt.repository.UserRepository;
import hugolini.login.auth.jwt.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtService jwtService;

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestParam String username, @RequestParam String password) {
        return userRepository.findByUsername(username)
                .filter(u -> u.getPassword().equals(password)) // simples para MVP
                .map(u -> ResponseEntity.ok(jwtService.generateToken(u.getUsername())))
                .orElse(ResponseEntity.status(401).body("Usuário ou senha inválidos"));
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody User user) {
        userRepository.save(user);
        return ResponseEntity.ok("Usuário registrado com sucesso");
    }
}
