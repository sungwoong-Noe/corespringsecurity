package io.security.corespringsecurity.security.provider;


import io.security.corespringsecurity.security.common.FormAuthenticationDetailsSource;
import io.security.corespringsecurity.security.common.FormWebAuthenticationDetails;
import io.security.corespringsecurity.security.service.AccountContext;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

//추가적인 검증을 하는 클래스
@RequiredArgsConstructor
public class FormAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {  //검증을 위한 구현
        //인증을 위한 검증

        String username = authentication.getName(); //로그인할 떄 입력한 id
        String password = (String)authentication.getCredentials(); //로그인할 때 사용한 비밀번호

         AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(username);
         if(!passwordEncoder.matches(password, accountContext.getAccount().getPassword())){
             throw new BadCredentialsException("BadCredentialsException");  //패스워드가 일치하지 않으면 인증 실패
         }


        FormWebAuthenticationDetails formWebAuthenticationDetails = (FormWebAuthenticationDetails) authentication.getDetails();
        String secretKey = formWebAuthenticationDetails.getSecretKey();
        if(secretKey == null || !"secret".equals(secretKey)){
            throw new InsufficientAuthenticationException("InsufficientAuthenticationException");
        }


        /**
         * 인증에 성공하게 되면 토큰을 만들어 반환, 2번째 생성자를 통해 만들어야 한다.
         * accountContext.getAccount() : 인증에 성공한 객체
         * credentials : password
         * accountContext.getAuthorities() : 권한 정보
         */
       return new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {  //
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
