package io.security.corespringsecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.corespringsecurity.domain.dto.AccountDto;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.thymeleaf.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {


    //ajax 요청시 json 방식으로 온 요청을 객체로 매핑해줘야 한다.
    private ObjectMapper objectMapper = new ObjectMapper();

    public AjaxLoginProcessingFilter() {
        super(new AntPathRequestMatcher("/api/login"));     //사용자가 url로 요청했을 때 매칭되면 작동 되도록 설정
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        if(!isAjax(request)){
            throw new IllegalStateException("Authentication is not supported");
        }

        //json 객체로 온 요청을 Dto 객체로 매핑해준다.
        //request.getReader()의 값을 읽어와서 Dto 클래스 형태로 담아서 받는다.
        AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);

        //null 체크
        if(StringUtils.isEmpty(accountDto.getUsername()) || StringUtils.isEmpty(accountDto.getPassword())) {
            throw new IllegalArgumentException("username or password is empty");
        }

        //통과되면 인증 처리를 해줘야 함.
        //ajax용 토큰을 만들어 인증 처리함
        return  new AjaxAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());
    }


    private boolean isAjax(HttpServletRequest request){
        if("XMLHttpRequest".equals(request.getHeader("X-Requested-With"))){
            return true;
        }
        return false;
    }

}
