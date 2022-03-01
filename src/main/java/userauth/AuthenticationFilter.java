package userauth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class AuthenticationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            String jwt = getJwtFromRequest(request);
            if (jwt.length() != 0 && TokenProvider.validateToken(jwt)) {
                String userId = TokenProvider.getUserIdFromJWT(jwt);

                // Id를 인증한다.
                UserAuthentication authentication = new UserAuthentication(userId, null, null);
                // 기본적으로 제공한 details 세팅
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                // 세션에서 계속 사용하기 위해 securityContext 에 Authentication 등록
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } else {
                if (jwt.length() == 0) {
                    request.setAttribute("unauthorization", "401 인증키 없음");
                }

                if (TokenProvider.validateToken(jwt)) {
                    request.setAttribute("unauthorization", "401-001 인증키 만료");
                }
            }
        } catch (Exception ex) {
            logger.error("Could not set user authentication in security context", ex);
        }

        filterChain.doFilter(request,response);
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken.length()!=0 && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring("Bearer ".length());
        }

        return null;
    }
}
