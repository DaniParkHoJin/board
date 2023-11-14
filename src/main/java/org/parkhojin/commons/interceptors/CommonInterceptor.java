package org.parkhojin.commons.interceptors;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.parkhojin.commons.Utils;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class CommonInterceptor implements HandlerInterceptor {
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        init(request);

        return true;
    }
    private void init(HttpServletRequest request){
        HttpSession session = request.getSession();

        String device = request.getParameter("device");
        if (device != null && !device.isBlank()) {
            session.setAttribute("device", device.toLowerCase().equals("mobile") ? "mobile": "pc");
        }
        String URI = request.getRequestURI();
        if (URI.indexOf("/member/login") == -1){
            Utils.loginInit(session);
        }
    }

}
