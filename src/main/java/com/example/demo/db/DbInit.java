package com.example.demo.db;

import com.example.demo.model.User;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
public class DbInit implements CommandLineRunner {

    private UserRepository userRepository;

    public DbInit(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public void run(String... args) throws Exception {
        User dan = new User("dan","dan","USER","");
        User admin = new User("admin","admin","ADMIN","ACCESS_TEST1,ACCESS_TEST2");
        User manager = new User("manager","manager","MANAGER","ACCESS_TEST1");

        List<User> users = Arrays.asList(dan,admin,manager);
        this.userRepository.saveAll(users);
    }
}
