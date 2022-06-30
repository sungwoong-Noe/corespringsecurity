package io.security.corespringsecurity.controller.user;


import io.security.corespringsecurity.domain.dto.AccountDto;
import io.security.corespringsecurity.domain.entity.Account;
import io.security.corespringsecurity.service.UserService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.Arrays;

@Controller
public class UserController {
	
	@Autowired
	private UserService userService;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@GetMapping(value="/users")
	public String createUser() throws Exception {

		return "user/login/register";
	}

	@PostMapping(value="/users")
	public String createUser(AccountDto accountDto) throws Exception {

		ModelMapper modelMapper = new ModelMapper();
		Account account = modelMapper.map(accountDto, Account.class);
		account.setPassword(passwordEncoder.encode(accountDto.getPassword()));
		userService.createUser(account);

		return "redirect:/";
	}

	@GetMapping(value="/mypage")
	public String myPage() throws Exception {

		return "user/mypage";
	}
}
