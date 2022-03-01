package userauth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * - AuthenticationEntryPoint 인터페이스
 * : 인증이 되지 않은 유저가 요청했을 때 동작한다
 */

@Slf4j
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException e) throws IOException {

        log.error("Responding with unauthorized error. Message - {}", e.getMessage());

        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getLocalizedMessage()); // 이전 프로젝트 참고

//        ErrorCode unAuthorizationCode = (ErrorCode) request.getAttribute("unauthorization.code");
//        request.setAttribute("response.failure.code", unAuthorizationCode.name());
//        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, unAuthorizationCode.message());
    }
}
