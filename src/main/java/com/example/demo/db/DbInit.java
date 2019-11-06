package com.example.demo.db;

import com.example.demo.model.User;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
public class DbInit implements CommandLineRunner {

    private UserRepository userRepository;

    private PasswordEncoder passwordEncoder;

    public DbInit(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        userRepository.deleteAll();

        User dan = new User("dan",passwordEncoder.encode("dan"),"ROLE_USER","");
        User admin = new User("admin",passwordEncoder.encode("admin"),"ROLE_ADMIN","ACCESS_TEST1,ACCESS_TEST2");
        User manager = new User("manager",passwordEncoder.encode("manager"),"ROLE_MANAGER","ACCESS_TEST1");

        List<User> users = Arrays.asList(dan,admin,manager);
        this.userRepository.saveAll(users);
    }
}
