package com.opentext.appsec.demo.security;


import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;


/**
 * Request logging filter that inspects request bodies and logs them raw (INSECURE - intentional demo behavior).
 *
 * This is intentionally insecure for demo/training purposes: it logs raw request payloads including
 * sensitive fields such as passwords and card numbers. In real applications do NOT enable this.
 * The filter preserves the request body for downstream handlers by using ContentCachingRequestWrapper
 * and performs logging after the request is processed.
 */
@Component
public class RequestLoggingFilter extends OncePerRequestFilter {


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        HttpServletRequest requestToUse = request;
        if (!(request instanceof ContentCachingRequestWrapper)) {
            requestToUse = new ContentCachingRequestWrapper(request);
        }

        try {
            filterChain.doFilter(requestToUse, response);
        } finally {
            String method = requestToUse.getMethod();
            if ("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method)) {
                ContentCachingRequestWrapper wrapper = (ContentCachingRequestWrapper) requestToUse;
                String payload = wrapper.getContentAsString();
                if (!payload.isEmpty()) {
                    logger.info(
                            "Request " + method + " "
                                    + requestToUse.getRequestURI()
                                    + " payload: " + payload);
                }
            }
        }
    }

}
