package org.parkhojin.medels.member;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.parkhojin.commons.Utils;
import org.parkhojin.entities.Member;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.Objects;

public class LoginSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        HttpSession session = request.getSession();

        Utils.loginInit(session);

        MemberInfo memberInfo = (MemberInfo)authentication.getPrincipal();
        Member member= memberInfo.getMember();
        session.setAttribute("loginMember", member);

        String redirectURL = Objects.requireNonNullElse(request.getParameter("redirectURL"), "/");

        response.sendRedirect(request.getContextPath() + redirectURL);
    }
}
