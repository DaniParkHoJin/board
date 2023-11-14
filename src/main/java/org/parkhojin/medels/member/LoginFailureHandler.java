package org.parkhojin.medels.member;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.parkhojin.commons.Utils;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;

public class LoginFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

        HttpSession session = request.getSession();

        Utils.loginInit(session);

        String email = request.getParameter("email");
        String password = request.getParameter("password");

        boolean isRequiredFieldCheck = false;

        session.setAttribute("email", email);

        if (email == null || email.isBlank()) {
            session.setAttribute("NotBlank_email", Utils.getMessages("NotBlank.email", "validation"));
            isRequiredFieldCheck = true;
        }
        if (password == null || password.isBlank()) {
            session.setAttribute("NotBlank_password", Utils.getMessages("NotBlank.password", "validation"));
            isRequiredFieldCheck = true;
        }

        if (!isRequiredFieldCheck) {
            session.setAttribute("globalError", Utils.getMessages("Login.fail", "validation"));

        }
        response.sendRedirect(request.getContextPath() + "/member/login");

    }
}