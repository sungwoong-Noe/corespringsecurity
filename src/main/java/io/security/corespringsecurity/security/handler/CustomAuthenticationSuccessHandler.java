package io.security.corespringsecurity.security.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {


    private RequestCache requestCache = new HttpSessionRequestCache();  //이 객체를 사용해서 이전 사용자 관련된 세션에 담긴 값을 가져와 사용

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();


    //여러가지 후속 작업을 할 수 있다
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        //기본 페이지 설정
        setDefaultTargetUrl("/");


        SavedRequest saveRequest = requestCache.getRequest(request, response);  //사용자가 인증에 성공하기 전에 요청을 했던 정보를 담는 객체이다.

        if(saveRequest != null){    //null일 수 있다 : 이전에 정보가 없이 요청하면 saveRequest가 null일 수 있다.
            String targetUrl = saveRequest.getRedirectUrl();    //이전에 가고자 했던 URL
            redirectStrategy.sendRedirect(request, response, targetUrl);    //이전에 가고자 했던 URL로 이동
        }else{
            //saveRequest가 null이면 기본적으로 이동할 페이지 설정
            redirectStrategy.sendRedirect(request, response, getDefaultTargetUrl());
        }
    }
}
