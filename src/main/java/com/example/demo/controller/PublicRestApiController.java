package com.example.demo.controller;
import com.example.demo.db.UserRepository;
import com.example.demo.model.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("api/public")
public class PublicRestApiController {

    private UserRepository userRepository;

    public PublicRestApiController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("test1")
    public String test1(){
        return "API Test 1";
    }

    @GetMapping("test2")
    public String test2(){
        return "API Test 2";
    }

    @GetMapping("users")
    public Iterable<User> allUsers(){
        return userRepository.findAll();
    }
}
